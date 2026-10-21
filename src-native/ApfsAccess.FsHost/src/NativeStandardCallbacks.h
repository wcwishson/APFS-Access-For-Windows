#pragma once

#include "NativeStandardFileInformation.h"
#include "NativeStandardShareModes.h"
#include "NativeStandardLocks.h"
#ifndef APFSACCESS_ENABLE_STANDARD_HARDLINK
#define APFSACCESS_ENABLE_STANDARD_HARDLINK 0
#endif
#if APFSACCESS_ENABLE_STANDARD_HARDLINK
#include "NativeHardLinkExecutor.h"
#endif

namespace native_standard
{
namespace wire = apfsaccess::fshost::standard_mount;

struct Reply
{
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    std::uint64_t handle = 0;
    std::uint32_t file_status = 0, granted = 0, count = 0;
    Bytes bytes;
};

class Callbacks
{
    struct Entry
    {
        OpenContext* open = nullptr;
        wire::Epoch client{};
        std::uint32_t share = 0, options = 0;
        std::uint64_t position = 0, id = 0;
        std::wstring stream;
        bool cleaned = false, read_observed = false, delete_on_close = false;
    };
    MountContext& context_;
    FSP_FILE_SYSTEM fs_{};
    HANDLE token_ = nullptr;
    wire::Epoch epoch_{};
    std::uint64_t next_handle_ = 1;
    std::map<std::uint64_t, Entry> entries_;
    std::set<wire::Epoch> clients_;
    wire::RangeLocks locks_;
    bool failed_ = false;

    NTSTATUS Descriptor(const std::wstring& path, Bytes& bytes)
    {
        SIZE_T size = 0;
        auto status = CB_GetSecurityByName(&fs_, const_cast<PWSTR>(path.c_str()), nullptr, nullptr, &size);
        if (status != STATUS_BUFFER_OVERFLOW || !size || size > wire::MaximumIoBytes) return status;
        bytes.resize(size);
        status = CB_GetSecurityByName(&fs_, const_cast<PWSTR>(path.c_str()), nullptr, bytes.data(), &size);
        if (!NT_SUCCESS(status)) return status;
        if (size != bytes.size() || !ValidBoundedWindowsSecurity(bytes)) return STATUS_INVALID_SECURITY_DESCR;
        return STATUS_SUCCESS;
    }
    NTSTATUS Access(PSECURITY_DESCRIPTOR descriptor, DWORD desired, DWORD& granted)
    {
        GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
        MapGenericMask(&desired, &mapping);
        alignas(PRIVILEGE_SET) std::array<std::byte, 4096> privileges{};
        DWORD bytes = static_cast<DWORD>(privileges.size()); BOOL allowed = FALSE;
        if (!AccessCheck(descriptor, token_, desired, &mapping,
                reinterpret_cast<PPRIVILEGE_SET>(privileges.data()), &bytes, &granted, &allowed) || !allowed)
            return STATUS_ACCESS_DENIED;
        return STATUS_SUCCESS;
    }
    NTSTATUS AccessPath(const std::wstring& path, DWORD desired, DWORD& granted)
    {
        Bytes descriptor;
        const auto status = Descriptor(path, descriptor);
        return NT_SUCCESS(status) ? Access(descriptor.data(), desired, granted) : status;
    }
    std::wstring StreamKey(const OpenContext& open)
    {
        if (open.native_xattr) return L"xattr:" + Utf8ToWide(open.native_xattr_name);
        return ToLowerInvariant(open.stream_name);
    }
    NTSTATUS Share(const std::shared_ptr<Node>& node, std::wstring_view stream, DWORD access, DWORD share)
    {
        if (!node || !node->object_id) return STATUS_NOT_SUPPORTED;
        std::array<wire::ShareOpen, 4096> held{};
        std::size_t count = 0;
        for (const auto& [id, entry] : entries_)
        {
            (void)id;
            if (!entry.open || entry.cleaned) continue;
            if (count == held.size()) return STATUS_TOO_MANY_OPENED_FILES;
            held[count++] = {entry.open->node->object_id, entry.stream, entry.open->granted_access, entry.share};
        }
        const auto result = wire::CheckShareAdmission({node->object_id, stream, access, share}, {held.data(), count});
        return result == wire::ShareAdmission::Allowed ? STATUS_SUCCESS :
            result == wire::ShareAdmission::SharingViolation ? STATUS_SHARING_VIOLATION : STATUS_INVALID_PARAMETER;
    }
    Entry* Handle(wire::Reader& reader, const wire::Epoch& client)
    {
        wire::Epoch owner{}; std::uint64_t id = 0;
        if (!reader.Identity(owner) || !reader.U64(id) || owner != epoch_) return nullptr;
        const auto found = entries_.find(id);
        if (found == entries_.end() || !found->second.open || found->second.client != client) return nullptr;
        return &found->second;
    }
    NTSTATUS Cleanup(Entry& entry)
    {
        if (entry.cleaned) return STATUS_SUCCESS;
        if (entry.delete_on_close)
        {
            const auto armed = CB_SetDelete(&fs_, entry.open, nullptr, TRUE);
            if (!NT_SUCCESS(armed)) { failed_ = true; return armed; }
        }
        ULONG flags = entry.open->delete_on_cleanup || entry.open->delete_on_close_requested ? FspCleanupDelete : 0u;
        if (entry.read_observed) flags |= FspCleanupSetLastAccessTime;
        CB_Cleanup(&fs_, entry.open, nullptr, flags);
        locks_.Cleanup(entry.id);
        entry.cleaned = true;
        const auto status = CB_Flush(&fs_, nullptr, nullptr);
        if (!NT_SUCCESS(status)) failed_ = true;
        return status;
    }
    NTSTATUS Close(Entry& entry)
    {
        const auto status = Cleanup(entry);
        locks_.Cleanup(entry.id);
        auto* open = entry.open; entry.open = nullptr; CB_Close(&fs_, open);
        const auto final_status = CB_Flush(&fs_, nullptr, nullptr);
        if (!NT_SUCCESS(final_status)) failed_ = true;
        return NT_SUCCESS(status) ? final_status : status;
    }
    NTSTATUS DeleteSharing(const std::shared_ptr<Node>& node, const Entry* self)
    {
        if (!node) return STATUS_SUCCESS;
        for (const auto& [id, entry] : entries_)
        {
            (void)id;
            if (&entry != self && entry.open && !entry.cleaned && entry.open->node &&
                entry.open->node->object_id == node->object_id && !(entry.share & FILE_SHARE_DELETE))
                return STATUS_SHARING_VIOLATION;
        }
        return STATUS_SUCCESS;
    }
    NTSTATUS TargetName(std::span<const std::byte> bytes, std::wstring& target, bool& replace)
    {
        if (bytes.size() < 24 || bytes[0] > std::byte{1} ||
            std::any_of(bytes.begin() + 1, bytes.begin() + 16, [](auto b) { return b != std::byte{}; }))
            return STATUS_INVALID_PARAMETER;
        const auto length = wire::GetLittle(bytes.subspan(16, 4));
        if (!length || length % 2 || length > bytes.size() - 20 || bytes.size() != (std::max)(std::size_t(24), std::size_t(20 + length)) ||
            std::any_of(bytes.begin() + 20 + length, bytes.end(), [](auto b) { return b != std::byte{}; }))
            return STATUS_INVALID_PARAMETER;
        Bytes encoded_name(4 + length);
        wire::PutLittle(std::span(encoded_name).first(4), length / 2);
        std::copy(bytes.begin() + 20, bytes.begin() + 20 + length, encoded_name.begin() + 4);
        wire::Reader name(encoded_name);
        if (!name.String(target) || !name.Done() || target.empty()) return STATUS_INVALID_PARAMETER;
        if (target.front() != L'\\') target.insert(target.begin(), L'\\');
        if (!wire::ValidRelativePath(target) || target == L"\\" || SplitNamedStreamPathNormalized(target).is_named_stream)
            return STATUS_INVALID_PARAMETER;
        replace = bytes[0] != std::byte{};
        return STATUS_SUCCESS;
    }
    NTSTATUS Rename(Entry& entry, std::span<const std::byte> bytes)
    {
        std::wstring target;
        bool replace = false;
        const auto parsed = TargetName(bytes, target, replace);
        if (!NT_SUCCESS(parsed)) return parsed;
        if (!(entry.open->granted_access & DELETE)) return STATUS_ACCESS_DENIED;
        std::wstring source;
        bool directory = false;
        {
            std::lock_guard names(context_.mutex);
            if (!entry.open->node || entry.open->node->namespace_detached) return STATUS_DELETE_PENDING;
            source = entry.open->node->path;
            directory = entry.open->node->is_directory;
        }
        const auto source_share = DeleteSharing(entry.open->node, &entry);
        if (!NT_SUCCESS(source_share)) return source_share;
        DWORD granted = 0;
        const auto parent = ParentOfNormalizedPath(target);
        const auto parent_access = AccessPath(parent, directory ? FILE_ADD_SUBDIRECTORY : FILE_ADD_FILE, granted);
        if (!NT_SUCCESS(parent_access)) return parent_access;
        Bytes descriptor;
        const auto exists = Descriptor(target, descriptor);
        if (NT_SUCCESS(exists))
        {
            if (!replace) return STATUS_OBJECT_NAME_COLLISION;
            const auto target_node = FindNodeNormalized(&context_, target);
            const auto shared = DeleteSharing(target_node, &entry);
            if (!NT_SUCCESS(shared)) return shared;
            if (!NT_SUCCESS(Access(descriptor.data(), DELETE, granted)) &&
                !NT_SUCCESS(AccessPath(parent, FILE_DELETE_CHILD, granted))) return STATUS_ACCESS_DENIED;
        }
        else if (exists != STATUS_OBJECT_NAME_NOT_FOUND) return exists;
        return CB_Rename(&fs_, entry.open, source.data(), target.data(), replace);
    }
#if APFSACCESS_ENABLE_STANDARD_HARDLINK
    NTSTATUS Link(Entry& entry, std::span<const std::byte> bytes)
    {
        if (!(Features(context_) & 32)) return STATUS_NOT_SUPPORTED;
        std::wstring target;
        bool replace = false;
        const auto parsed = TargetName(bytes, target, replace);
        if (!NT_SUCCESS(parsed)) return parsed;
        if (entry.open->named_stream || entry.open->native_xattr || entry.delete_on_close ||
            entry.open->delete_on_cleanup || entry.open->delete_on_close_requested)
            return STATUS_INVALID_PARAMETER;
        if (!entry.open->node || entry.open->node->node_kind != NodeKind::RegularFile)
            return STATUS_FILE_IS_A_DIRECTORY;
        const auto parent = ParentOfNormalizedPath(target);
        DWORD granted = 0;
        const auto parent_access = AccessPath(parent, FILE_ADD_FILE, granted);
        if (!NT_SUCCESS(parent_access)) return parent_access;
        const auto directory = FindNodeNormalized(&context_, parent);
        if (!directory || !directory->is_directory) return STATUS_OBJECT_PATH_NOT_FOUND;
        const auto shared = Share(directory, L"", FILE_ADD_FILE, 7);
        if (!NT_SUCCESS(shared)) return shared;
        Bytes existing;
        const auto observed = Descriptor(target, existing);
        if (NT_SUCCESS(observed)) return replace ? STATUS_NOT_SUPPORTED : STATUS_OBJECT_NAME_COLLISION;
        if (observed != STATUS_OBJECT_NAME_NOT_FOUND) return observed;
        ExternalMutationRequestScope admission(&context_);
        if (!admission.Acquired()) return STATUS_VOLUME_DISMOUNTED;
        MutationCallbackScope mutation(&context_);
        const auto drained = DrainNativeMutationsByPolicy(&context_, L"StandardHardLink", false, true);
        if (!NT_SUCCESS(drained)) return drained;
        if (!FinalizeMutationJournalBestEffort(&context_, L"StandardHardLink")) return STATUS_UNSUCCESSFUL;
        apfsaccess::rw::NativeHardLinkOpenEntry source_entry, directory_entry;
        {
            std::lock_guard metadata(context_.metadata_mutex);
            if (!CaptureNativeHardLinkOpenEntry(*context_.metadata_store, entry.open->node->path, source_entry) ||
                !CaptureNativeHardLinkOpenEntry(*context_.metadata_store, parent, directory_entry) ||
                source_entry.object_id != entry.open->node->object_id || directory_entry.object_id != directory->object_id)
                return STATUS_INVALID_HANDLE;
        }
        NativeHardLinkExecutionResult result;
        return ExecuteNativeHardLinkUnderMutationGate(context_, entry.open->node, source_entry,
            directory, directory_entry, LeafNameOfNormalizedPath(target), result);
    }
#endif
    NTSTATUS SetFile(wire::Reader& reader, Entry& entry)
    {
        std::uint32_t information = 0, length = 0;
        std::span<const std::byte> bytes;
        if (!reader.U32(information) || !reader.U32(length) || length > wire::MaximumIoBytes ||
            !reader.Bytes(length, bytes) || !reader.Done()) return STATUS_INVALID_PARAMETER;
        FSP_FSCTL_FILE_INFO info{};
        switch (information)
        {
        case 10: return Rename(entry, bytes);
#if APFSACCESS_ENABLE_STANDARD_HARDLINK
        case 11: return Link(entry, bytes);
#endif
        case 4:
            if (bytes.size() != 40 || wire::GetLittle(bytes.subspan(36, 4))) return STATUS_INVALID_PARAMETER;
            for (std::size_t i = 0; i < 4; ++i)
                if (wire::GetLittle(bytes.subspan(i * 8, 8)) > INT64_MAX) return STATUS_NOT_SUPPORTED;
            return CB_SetBasicInfo(&fs_, entry.open, static_cast<UINT32>(wire::GetLittle(bytes.subspan(32, 4))),
                wire::GetLittle(bytes.subspan(0, 8)), wire::GetLittle(bytes.subspan(8, 8)),
                wire::GetLittle(bytes.subspan(16, 8)), wire::GetLittle(bytes.subspan(24, 8)), &info);
        case 13:
            if (bytes.size() != 1 || std::to_integer<unsigned>(bytes[0]) > 1) return STATUS_INVALID_PARAMETER;
            return CB_SetDelete(&fs_, entry.open, nullptr, bytes[0] != std::byte{});
        case 19:
        case 20:
            if (bytes.size() != 8 || wire::GetLittle(bytes) > INT64_MAX) return STATUS_INVALID_PARAMETER;
            return CB_SetFileSize(&fs_, entry.open, wire::GetLittle(bytes), information == 19, &info);
        default: return STATUS_NOT_SUPPORTED;
        }
    }
    NTSTATUS Directory(wire::Reader& reader, Entry& entry, Reply& reply)
    {
        std::uint32_t information = 0;
        std::wstring pattern;
        if (!reader.U32(information) || !reader.String(pattern) || !reader.Done() || pattern.empty() ||
            pattern.find_first_of(L"\\/:") != std::wstring::npos) return STATUS_INVALID_PARAMETER;
        const auto fixed = information == 1 ? 64u : information == 2 ? 68u : information == 3 ? 94u :
            information == 12 ? 12u : information == 37 ? 104u : information == 38 ? 80u : 0u;
        if (!fixed) return STATUS_INVALID_INFO_CLASS;
        Bytes raw(wire::MaximumIoBytes);
        std::wstring marker;
        std::size_t previous = 0;
        bool have_previous = false, complete = false;
        while (!complete)
        {
            ULONG done = 0;
            const auto status = CB_ReadDirectory(&fs_, entry.open, nullptr, marker.empty() ? nullptr : marker.data(),
                raw.data(), static_cast<ULONG>(raw.size()), &done);
            if (status == STATUS_NO_MORE_FILES) break;
            if (!NT_SUCCESS(status)) return status;
            if (done > raw.size()) return STATUS_IO_DEVICE_ERROR;
            std::size_t offset = 0;
            const auto prior_marker = marker;
            while (offset + 2 <= done)
            {
                const auto size = wire::GetLittle(std::span(raw).subspan(offset, 2));
                if (!size) { complete = true; break; }
                const auto name_offset = offsetof(FSP_FSCTL_DIR_INFO, FileNameBuf);
                if (size < name_offset || size > done - offset || (size - name_offset) % 2) return STATUS_IO_DEVICE_ERROR;
                FSP_FSCTL_FILE_INFO file{};
                memcpy(&file, raw.data() + offset + offsetof(FSP_FSCTL_DIR_INFO, FileInfo), sizeof(file));
                OverlaySparseAttributes(context_, file);
                const auto name_units = (size - name_offset) / 2;
                if (name_units > wire::MaximumPathUnits || ++reply.count > 4096) return STATUS_NOT_SUPPORTED;
                marker.resize(static_cast<std::size_t>(name_units));
                for (std::size_t i = 0; i < name_units; ++i)
                    marker[i] = static_cast<wchar_t>(wire::GetLittle(std::span(raw).subspan(offset + name_offset + i * 2, 2)));
                if (marker.empty() || marker.find_first_of(L"\\/\0", 0, 3) != std::wstring::npos) return STATUS_IO_DEVICE_ERROR;
                const auto aligned = (reply.bytes.size() + 7) & ~std::size_t(7);
                if (aligned > wire::MaximumFrameBytes - wire::HeaderBytes - 32 ||
                    fixed + name_units * 2 > wire::MaximumFrameBytes - wire::HeaderBytes - 32 - aligned)
                    return STATUS_NOT_SUPPORTED;
                if (have_previous)
                {
                    reply.bytes.resize(aligned);
                    wire::PutLittle(std::span(reply.bytes).subspan(previous, 4), aligned - previous);
                }
                previous = reply.bytes.size(); have_previous = true;
                Number(reply.bytes, 0, 4); Number(reply.bytes, 0, 4);
                if (information != 12)
                {
                    for (auto time : {file.CreationTime, file.LastAccessTime, file.LastWriteTime, file.ChangeTime}) Number(reply.bytes, time, 8);
                    Number(reply.bytes, file.FileSize, 8); Number(reply.bytes, file.AllocationSize, 8);
                    Number(reply.bytes, file.FileAttributes, 4);
                }
                Number(reply.bytes, name_units * 2, 4);
                if (information == 2 || information == 3 || information == 37 || information == 38) Number(reply.bytes, 0, 4);
                if (information == 3 || information == 37) reply.bytes.resize(reply.bytes.size() + 26);
                if (information == 37) { Number(reply.bytes, 0, 2); Number(reply.bytes, file.IndexNumber, 8); }
                if (information == 38) { Number(reply.bytes, 0, 4); Number(reply.bytes, file.IndexNumber, 8); }
                for (auto ch : marker) Number(reply.bytes, static_cast<std::uint16_t>(ch), 2);
                if (reply.bytes.size() - previous != fixed + name_units * 2) return STATUS_IO_DEVICE_ERROR;
                offset += (static_cast<std::size_t>(size) + 7) & ~std::size_t(7);
            }
            if (!complete && (marker.empty() || marker == prior_marker)) return STATUS_IO_DEVICE_ERROR;
        }
        return STATUS_SUCCESS;
    }
    NTSTATUS Open(wire::Reader& reader, const wire::Epoch& client, Reply& reply)
    {
        std::uint32_t desired = 0, share = 0, attributes = 0, disposition = 0, options = 0;
        std::wstring path;
        if (!reader.U32(desired) || !reader.U32(share) || !reader.U32(attributes) ||
            !reader.U32(disposition) || !reader.U32(options) || !reader.String(path) || !reader.Done() ||
            !wire::ValidRelativePath(path) || !wire::NonzeroEpoch(client) || (share & ~7u) || disposition > 5 ||
            (options & FILE_OPEN_BY_FILE_ID)) return STATUS_INVALID_PARAMETER;
        if (entries_.size() >= 4096 || next_handle_ == UINT64_MAX) return STATUS_TOO_MANY_OPENED_FILES;
        if (path.empty()) path = L"\\";
        const auto stream_path = SplitNamedStreamPathNormalized(path);
        if (stream_path.is_named_stream) return STATUS_NOT_SUPPORTED;
        auto node = FindNodeNormalized(&context_, stream_path.is_named_stream ? stream_path.base_path : path);
        bool exists = false;
        {
            Bytes descriptor;
            const auto observed = Descriptor(path, descriptor);
            if (observed == STATUS_REPARSE) return STATUS_NOT_SUPPORTED;
            if (NT_SUCCESS(observed)) exists = true;
            else if (observed != STATUS_OBJECT_NAME_NOT_FOUND) return observed;
        }
        if (exists && disposition == 2) return STATUS_OBJECT_NAME_COLLISION;
        if (!exists && (disposition == 1 || disposition == 4)) return STATUS_OBJECT_NAME_NOT_FOUND;
        DWORD granted = 0;
        PSECURITY_DESCRIPTOR created_security = nullptr;
        ScopeExit release_security{[&] { if (created_security) DestroyPrivateObjectSecurity(&created_security); }};
        if (exists)
        {
            const auto status = AccessPath(path, desired, granted);
            if (!NT_SUCCESS(status)) return status;
            if (node && !node->is_directory && (granted & (FILE_WRITE_DATA | FILE_APPEND_DATA)) &&
                (VisibleWindowsAttributes(*node) & FILE_ATTRIBUTE_READONLY)) return STATUS_ACCESS_DENIED;
            const auto key = stream_path.is_named_stream ? ToLowerInvariant(stream_path.stream_name) : std::wstring();
            const auto shared = Share(node, key, granted, share);
            if (!NT_SUCCESS(shared)) return shared;
        }
        else
        {
            if (stream_path.is_named_stream) return STATUS_NOT_SUPPORTED;
            Bytes parent;
            const auto status = Descriptor(ParentOfNormalizedPath(path), parent);
            if (!NT_SUCCESS(status)) return status;
            DWORD parent_granted = 0;
            const auto parent_access = Access(parent.data(), (options & FILE_DIRECTORY_FILE) ? FILE_ADD_SUBDIRECTORY : FILE_ADD_FILE, parent_granted);
            if (!NT_SUCCESS(parent_access)) return parent_access;
            GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
            if (!CreatePrivateObjectSecurityEx(parent.data(), nullptr, &created_security, nullptr,
                    (options & FILE_DIRECTORY_FILE) != 0, SEF_DACL_AUTO_INHERIT, token_, &mapping))
                return STATUS_INVALID_SECURITY_DESCR;
            const auto child_access = Access(created_security, desired, granted);
            if (!NT_SUCCESS(child_access)) return child_access;
        }
        if ((options & FILE_DELETE_ON_CLOSE) && !(granted & DELETE)) return STATUS_ACCESS_DENIED;
        if (exists && (disposition == 0 || disposition == 4 || disposition == 5) && !(granted & FILE_WRITE_DATA))
            return STATUS_ACCESS_DENIED;
        if (exists && disposition == 0 && !(granted & DELETE)) return STATUS_ACCESS_DENIED;
        const auto id = next_handle_++;
        auto [where, inserted] = entries_.try_emplace(id);
        if (!inserted) return STATUS_INSUFFICIENT_RESOURCES;
        auto& entry = where->second;
        entry.client = client; entry.share = share; entry.options = options; entry.id = id;
        FSP_FSCTL_FILE_INFO info{};
        PVOID opened = nullptr;
        const auto callback_options = options & ~FILE_DELETE_ON_CLOSE;
        auto status = exists ? CB_Open(&fs_, path.data(), callback_options, granted, &opened, &info) :
            CB_Create(&fs_, path.data(), callback_options, granted, attributes, created_security, 0, &opened, &info);
        entry.open = static_cast<OpenContext*>(opened);
        if (!NT_SUCCESS(status)) { if (entry.open) Close(entry); entries_.erase(where); return status; }
        entry.stream = StreamKey(*entry.open);
        if (exists && (disposition == 0 || disposition == 4 || disposition == 5))
        {
            status = CB_Overwrite(&fs_, entry.open, attributes, disposition == 0, 0, &info);
            if (!NT_SUCCESS(status)) { Close(entry); entries_.erase(where); return status; }
        }
        reply.handle = id; reply.granted = granted;
        entry.delete_on_close = (options & FILE_DELETE_ON_CLOSE) != 0;
        reply.file_status = exists ? (disposition == 0 ? 0u : disposition >= 4 ? 3u : 1u) : 2u;
        return STATUS_SUCCESS;
    }
#if APFSACCESS_ENABLE_STANDARD_SPARSE
    NTSTATUS Sparse(wire::Reader& reader, Entry& entry, wire::Operation operation, Reply& reply)
    {
        using Store = apfsaccess::rw::MetadataStore;
        if (!(Features(context_) & 8) || entry.open->named_stream || entry.open->native_xattr ||
            !entry.open->node || entry.open->node->node_kind != NodeKind::RegularFile) return STATUS_NOT_SUPPORTED;
        std::uint64_t offset = 0, length = 0;
        std::uint32_t value = 0;
        if (operation == wire::Operation::SetSparse)
        {
            if (!reader.U32(value) || value > 1 || !reader.Done()) return STATUS_INVALID_PARAMETER;
        }
        else
        {
            std::uint64_t second = 0;
            if (!reader.U64(offset) || !reader.U64(second) || offset > INT64_MAX) return STATUS_INVALID_PARAMETER;
            if (operation == wire::Operation::ZeroRange)
            {
                if (second < offset || second > INT64_MAX || !reader.Done()) return STATUS_INVALID_PARAMETER;
                length = second - offset;
            }
            else
            {
                if (second > std::uint64_t(INT64_MAX) - offset || !reader.U32(value) ||
                    value > wire::MaximumFrameBytes - wire::HeaderBytes - 32 || !reader.Done()) return STATUS_INVALID_PARAMETER;
                length = second;
            }
        }
        if (operation == wire::Operation::QueryAllocatedRanges)
        {
            if (!(entry.open->granted_access & FILE_READ_DATA)) return STATUS_ACCESS_DENIED;
            FSP_FSCTL_FILE_INFO flushed_info{};
            const auto flushed = CB_Flush(&fs_, entry.open, &flushed_info);
            if (!NT_SUCCESS(flushed)) return flushed;
            std::vector<apfsaccess::rw::NativeSparseAllocatedRange> ranges;
            std::string error;
            {
                std::lock_guard commit(context_.commit_mutex); std::shared_lock reads(context_.committed_read_gate);
                std::lock_guard metadata(context_.metadata_mutex);
                apfsaccess::rw::NativeSparseOpenEntry binding;
                if (!CaptureNativeStandardOpenEntry(context_, *entry.open, binding)) return STATUS_INVALID_HANDLE;
                const auto queried = context_.metadata_store->WithNativeSparseSession(binding,
                    [&](const auto& session, auto& why) {
                        return context_.metadata_store->QueryNativeAllocatedRangesV2(session, offset, length, 4096, ranges, why);
                    }, error);
                if (!queried) return STATUS_NOT_SUPPORTED;
            }
            if (!ranges.empty() && value < 16) return STATUS_BUFFER_TOO_SMALL;
            const auto count = (std::min)(ranges.size(), std::size_t(value / 16));
            for (std::size_t i = 0; i < count; ++i) { Number(reply.bytes, ranges[i].offset, 8); Number(reply.bytes, ranges[i].length, 8); }
            reply.count = static_cast<std::uint32_t>(reply.bytes.size());
            return count == ranges.size() ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;
        }
        if (!(entry.open->granted_access & FILE_WRITE_DATA)) return STATUS_ACCESS_DENIED;
        FSP_FSCTL_FILE_INFO info{};
        const auto observed = CB_GetFileInfo(&fs_, entry.open, &info);
        if (!NT_SUCCESS(observed)) return observed;
        const auto affected = operation == wire::Operation::ZeroRange ?
            (offset < info.FileSize ? (std::min)(length, info.FileSize - offset) : 0) : info.FileSize;
        if (!locks_.AllowsIo(entry.id, entry.open->node->object_id, entry.stream,
                operation == wire::Operation::ZeroRange ? offset : 0, affected, true)) return STATUS_FILE_LOCK_CONFLICT;
        const auto ticks = ToFileTimeValue(UtcNow());
        constexpr std::uint64_t epoch = 116444736000000000ULL;
        if (ticks <= epoch || ticks - epoch > UINT64_MAX / 100) return STATUS_INVALID_PARAMETER;
        apfsaccess::rw::NativeSparseRequest request;
        request.action = operation == wire::Operation::SetSparse ? apfsaccess::rw::NativeSparseAction::SetSparse : apfsaccess::rw::NativeSparseAction::ZeroRange;
        request.sparse = operation == wire::Operation::SetSparse && value != 0;
        request.offset = offset; request.length = length; request.timestamp_ns = (ticks - epoch) * 100;
        return ExecuteNativeSparse(context_, *entry.open, request);
    }
#endif
#if APFSACCESS_ENABLE_STANDARD_CLONE_RANGE
    NTSTATUS CloneRange(wire::Reader& reader, Entry& source, const wire::Epoch& client)
    {
        auto* target = Handle(reader, client);
        if (!target || target->cleaned) return STATUS_INVALID_HANDLE;
        if (!(Features(context_) & 16)) return STATUS_NOT_SUPPORTED;
        std::uint64_t source_offset = 0, target_offset = 0, length = 0;
        if (!reader.U64(source_offset) || !reader.U64(target_offset) || !reader.U64(length) || !reader.Done() ||
            source_offset > INT64_MAX || target_offset > INT64_MAX || !length ||
            length > std::uint64_t(INT64_MAX) - source_offset || length > std::uint64_t(INT64_MAX) - target_offset)
            return STATUS_INVALID_PARAMETER;
        if (source.open->named_stream || source.open->native_xattr || target->open->named_stream || target->open->native_xattr ||
            !source.open->node || !target->open->node || source.open->node->node_kind != NodeKind::RegularFile ||
            target->open->node->node_kind != NodeKind::RegularFile) return STATUS_NOT_SUPPORTED;
        if (!(source.open->granted_access & FILE_READ_DATA) || !(target->open->granted_access & FILE_WRITE_DATA))
            return STATUS_ACCESS_DENIED;
        if (!locks_.AllowsIo(source.id, source.open->node->object_id, source.stream, source_offset, length, false) ||
            !locks_.AllowsIo(target->id, target->open->node->object_id, target->stream, target_offset, length, true))
            return STATUS_FILE_LOCK_CONFLICT;
        const auto ticks = ToFileTimeValue(UtcNow());
        constexpr std::uint64_t epoch = 116444736000000000ULL;
        if (ticks <= epoch || ticks - epoch > UINT64_MAX / 100) return STATUS_INVALID_PARAMETER;
        return ExecuteNativeCloneRange(context_, *source.open, *target->open,
            {source_offset, target_offset, length, (ticks - epoch) * 100});
    }
#endif
    NTSTATUS Security(wire::Reader& reader, Entry& entry, bool set, Reply& reply)
    {
        std::uint32_t information = 0;
        if (!reader.U32(information)) return STATUS_INVALID_PARAMETER;
        constexpr DWORD known = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
            SACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION |
            PROTECTED_SACL_SECURITY_INFORMATION | UNPROTECTED_SACL_SECURITY_INFORMATION;
        if (!information || (information & ~known)) return STATUS_NOT_SUPPORTED;
        if (set)
        {
            std::uint32_t size = 0; std::span<const std::byte> bytes;
            if (!reader.U32(size) || size > wire::MaximumIoBytes || !reader.Bytes(size, bytes) || !reader.Done() ||
                !ValidBoundedWindowsSecurity(bytes)) return STATUS_INVALID_SECURITY_DESCR;
            return CB_SetSecurity(&fs_, entry.open, information, const_cast<std::byte*>(bytes.data()));
        }
        if (!reader.Done() || ((information & (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)) &&
                !(entry.open->granted_access & READ_CONTROL)) ||
            ((information & SACL_SECURITY_INFORMATION) && !(entry.open->granted_access & ACCESS_SYSTEM_SECURITY)))
            return STATUS_ACCESS_DENIED;
        SIZE_T length = 0;
        auto status = CB_GetSecurity(&fs_, entry.open, nullptr, &length);
        if (status != STATUS_BUFFER_OVERFLOW || !length || length > wire::MaximumIoBytes) return status;
        Bytes full(length);
        status = CB_GetSecurity(&fs_, entry.open, full.data(), &length);
        if (!NT_SUCCESS(status) || length != full.size() || !ValidBoundedWindowsSecurity(full)) return STATUS_INVALID_SECURITY_DESCR;
        DWORD needed = 0;
        GetPrivateObjectSecurity(full.data(), information, nullptr, 0, &needed);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !needed || needed > wire::MaximumIoBytes) return STATUS_INVALID_SECURITY_DESCR;
        reply.bytes.resize(needed);
        if (!GetPrivateObjectSecurity(full.data(), information, reply.bytes.data(), needed, &needed)) return STATUS_INVALID_SECURITY_DESCR;
        reply.bytes.resize(needed);
        return STATUS_SUCCESS;
    }
public:
    Callbacks(MountContext& context, const wire::Epoch& epoch, HANDLE token) : context_(context), token_(token), epoch_(epoch)
    { fs_.UserContext = &context_; }
    ~Callbacks()
    {
        (void)CloseAll();
    }
    Callbacks(const Callbacks&) = delete;
    Callbacks& operator=(const Callbacks&) = delete;
    bool Failed() const noexcept { return failed_; }
    NTSTATUS CloseAll() noexcept
    {
        NTSTATUS status = STATUS_SUCCESS;
        for (auto& [id, entry] : entries_)
        {
            (void)id;
            if (!entry.open) continue;
            try { const auto closed = Close(entry); if (!NT_SUCCESS(closed) && NT_SUCCESS(status)) status = closed; }
            catch (...) { failed_ = true; status = STATUS_IO_DEVICE_ERROR; }
        }
        entries_.clear();
        clients_.clear();
        return status;
    }
    NTSTATUS Disconnect(const wire::Epoch& client)
    {
        NTSTATUS status = STATUS_SUCCESS;
        for (auto at = entries_.begin(); at != entries_.end(); )
        {
            if (at->second.client != client) { ++at; continue; }
            const auto closed = Close(at->second);
            if (!NT_SUCCESS(closed) && NT_SUCCESS(status)) status = closed;
            at = entries_.erase(at);
        }
        clients_.erase(client);
        return status;
    }
    Reply Invoke(const wire::Header& header, std::span<const std::byte> bytes)
    {
        Reply reply;
        if (failed_) { reply.status = STATUS_IO_DEVICE_ERROR; return reply; }
        wire::Reader reader(bytes);
        if (header.operation == wire::Operation::Open)
        {
            if (!wire::NonzeroEpoch(header.epoch)) { reply.status = STATUS_INVALID_PARAMETER; return reply; }
            if (!clients_.contains(header.epoch))
            {
                if (clients_.size() == 16) { reply.status = STATUS_INSUFFICIENT_RESOURCES; return reply; }
                clients_.insert(header.epoch);
            }
            reply.status = Open(reader, header.epoch, reply); return reply;
        }
        if (header.operation == wire::Operation::QueryVolume)
        {
            std::uint32_t information = 0;
            reply.status = reader.U32(information) && reader.Done() ? VolumeInformation(context_, information, reply.bytes) : STATUS_INVALID_PARAMETER;
            return reply;
        }
        if (header.operation == wire::Operation::Disconnect)
        {
            reply.status = reader.Done() && clients_.contains(header.epoch) ? Disconnect(header.epoch) : STATUS_INVALID_PARAMETER;
            return reply;
        }
        const auto* start = bytes.data();
        auto* entry = Handle(reader, header.epoch);
        if (!entry) { reply.status = STATUS_INVALID_HANDLE; return reply; }
        if (header.operation == wire::Operation::Close)
        {
            if (!reader.Done()) { reply.status = STATUS_INVALID_PARAMETER; return reply; }
            const auto id = wire::GetLittle({start + 16, 8});
            reply.status = Close(*entry); entries_.erase(id); return reply;
        }
        if (entry->cleaned) { reply.status = STATUS_FILE_CLOSED; return reply; }
        FSP_FSCTL_FILE_INFO info{};
        switch (header.operation)
        {
#if APFSACCESS_ENABLE_STANDARD_CLONE_RANGE
        case wire::Operation::CloneRange:
            reply.status = CloneRange(reader, *entry, header.epoch); break;
#endif
#if APFSACCESS_ENABLE_STANDARD_SPARSE
        case wire::Operation::SetSparse:
        case wire::Operation::ZeroRange:
        case wire::Operation::QueryAllocatedRanges:
            reply.status = Sparse(reader, *entry, header.operation, reply); break;
#endif
        case wire::Operation::Lock:
        case wire::Operation::Unlock:
        {
            if (entry->open->node->node_kind != NodeKind::RegularFile || entry->open->node->is_directory)
            { reply.status = STATUS_INVALID_DEVICE_REQUEST; break; }
            std::uint64_t offset = 0, length = 0;
            std::uint32_t exclusive = 0;
            if (!reader.U64(offset) || !reader.U64(length) || !reader.U32(exclusive) || exclusive > 1 || !reader.Done())
            { reply.status = STATUS_INVALID_PARAMETER; break; }
            if (!(entry->open->granted_access & (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA)))
            { reply.status = STATUS_ACCESS_DENIED; break; }
            const auto result = header.operation == wire::Operation::Unlock ? locks_.Release(entry->id, offset, length) :
                locks_.Acquire(entry->id, entry->open->node->object_id, entry->stream, offset, length, exclusive != 0);
            reply.status = result == wire::LockAdmission::Allowed ? STATUS_SUCCESS :
                result == wire::LockAdmission::Conflict ? STATUS_LOCK_NOT_GRANTED :
                result == wire::LockAdmission::NotLocked ? STATUS_RANGE_NOT_LOCKED :
                result == wire::LockAdmission::Exhausted ? STATUS_INSUFFICIENT_RESOURCES : STATUS_INVALID_PARAMETER;
            break;
        }
        case wire::Operation::Cleanup:
            reply.status = reader.Done() ? Cleanup(*entry) : STATUS_INVALID_PARAMETER; break;
        case wire::Operation::Flush:
            reply.status = reader.Done() ? CB_Flush(&fs_, entry->open, &info) : STATUS_INVALID_PARAMETER; break;
        case wire::Operation::Read:
        case wire::Operation::Write:
        {
            std::uint64_t offset = 0; std::uint32_t length = 0;
            if (!reader.U64(offset) || !reader.U32(length) || length > wire::MaximumIoBytes || offset > INT64_MAX ||
                length > static_cast<std::uint64_t>(INT64_MAX) - offset)
            { reply.status = STATUS_INVALID_PARAMETER; break; }
            ULONG transferred = 0;
            if (header.operation == wire::Operation::Read)
            {
                if (!reader.Done()) { reply.status = STATUS_INVALID_PARAMETER; break; }
                if (!(entry->open->granted_access & FILE_READ_DATA)) { reply.status = STATUS_ACCESS_DENIED; break; }
                if (!locks_.AllowsIo(entry->id, entry->open->node->object_id, entry->stream, offset, length, false))
                { reply.status = STATUS_FILE_LOCK_CONFLICT; break; }
                reply.bytes.resize(length);
                reply.status = length ? CB_Read(&fs_, entry->open, reply.bytes.data(), offset, length, &transferred) : STATUS_SUCCESS;
                if (transferred > length) { failed_ = true; reply.status = STATUS_IO_DEVICE_ERROR; break; }
                if (NT_SUCCESS(reply.status)) reply.bytes.resize(transferred); else reply.bytes.clear();
                if (transferred) entry->read_observed = true;
            }
            else
            {
                std::span<const std::byte> payload;
                if (!reader.Bytes(length, payload) || !reader.Done()) { reply.status = STATUS_INVALID_PARAMETER; break; }
                const auto access = entry->open->granted_access;
                if (!(access & (FILE_WRITE_DATA | FILE_APPEND_DATA))) { reply.status = STATUS_ACCESS_DENIED; break; }
                std::uint64_t effective_offset = offset;
                if (!(access & FILE_WRITE_DATA))
                {
                    reply.status = CB_GetFileInfo(&fs_, entry->open, &info);
                    if (!NT_SUCCESS(reply.status)) break;
                    effective_offset = info.FileSize;
                }
                if (!locks_.AllowsIo(entry->id, entry->open->node->object_id, entry->stream, effective_offset, length, true))
                { reply.status = STATUS_FILE_LOCK_CONFLICT; break; }
                reply.status = length ? CB_Write(&fs_, entry->open, const_cast<std::byte*>(payload.data()), offset, length,
                    (access & FILE_WRITE_DATA) == 0, FALSE, &transferred, &info) : STATUS_SUCCESS;
                if (NT_SUCCESS(reply.status) && (entry->options & FILE_WRITE_THROUGH)) reply.status = CB_Flush(&fs_, entry->open, &info);
            }
            reply.count = transferred; break;
        }
        case wire::Operation::QueryFile:
        {
            std::uint32_t information = 0;
            if (!reader.U32(information) || !reader.Done()) { reply.status = STATUS_INVALID_PARAMETER; break; }
            if ((information == 4 || information == 18 || information == 34 || information == 35) &&
                !(entry->open->granted_access & FILE_READ_ATTRIBUTES)) { reply.status = STATUS_ACCESS_DENIED; break; }
            reply.status = CB_GetFileInfo(&fs_, entry->open, &info);
            if (NT_SUCCESS(reply.status)) reply.status = FileInformation(context_, *entry->open, info, information,
                entry->position, entry->options, reply.bytes);
            break;
        }
        case wire::Operation::QuerySecurity: reply.status = Security(reader, *entry, false, reply); break;
        case wire::Operation::SetSecurity: reply.status = Security(reader, *entry, true, reply); break;
        case wire::Operation::SetFile: reply.status = SetFile(reader, *entry); break;
        case wire::Operation::QueryDirectory:
            reply.status = (entry->open->granted_access & FILE_LIST_DIRECTORY) ? Directory(reader, *entry, reply) : STATUS_ACCESS_DENIED; break;
        default: reply.status = STATUS_NOT_SUPPORTED; break;
        }
        if (!NT_SUCCESS(reply.status) && !(header.operation == wire::Operation::QueryAllocatedRanges && reply.status == STATUS_BUFFER_OVERFLOW))
            reply.bytes.clear();
        return reply;
    }
};
}
