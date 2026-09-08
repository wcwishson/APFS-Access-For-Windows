// Included directly by main.cpp after the native journal/commit helpers.
// Callers hold MutationCallbackScope. No NTFS sidecar participates in this path.
#pragma once
#include <new>

bool NativeXattrVisibilityUnresolved(MountContext* c)
{
    return c->unjournaled_native_mutation || c->write_degraded || c->recovery_active;
}

NTSTATUS NativeXattrValue(MountContext* c, OpenContext* o, std::uint64_t offset,
    std::size_t length, std::vector<std::byte>& bytes, std::uint64_t& size)
{
    bytes.clear(); size = 0;
    if (!c || !o || !o->node || !o->native_xattr) return STATUS_INVALID_HANDLE;
    if (o->native_xattr->protocol)
    {
        constexpr std::string_view protocol = "APFS-XATTR/1\n";
        size = protocol.size();
        const auto count = offset >= size ? 0 : (std::min<std::uint64_t>)(length, size - offset);
        if (count)
        {
            const auto* first = reinterpret_cast<const std::byte*>(protocol.data()) + offset;
            bytes.assign(first, first + count);
        }
        return STATUS_SUCCESS;
    }
    if (NativeXattrVisibilityUnresolved(c)) return STATUS_IO_DEVICE_ERROR;
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (c->metadata_store)
    {
        std::lock_guard<std::mutex> metadata(c->metadata_mutex);
        if (c->metadata_store->IsRecoveryRequired()) return STATUS_IO_DEVICE_ERROR;
    }
#endif
    if (o->native_xattr->removed)
    {
        size = o->native_xattr->removed_value.size();
        const auto count = offset >= size ? 0 : (std::min<std::uint64_t>)(length, size - offset);
        if (count) bytes.assign(o->native_xattr->removed_value.begin() + static_cast<std::size_t>(offset),
            o->native_xattr->removed_value.begin() + static_cast<std::size_t>(offset + count));
        return STATUS_SUCCESS;
    }
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!c->metadata_store || !o->node->object_id) return STATUS_NOT_SUPPORTED;
    std::shared_lock<std::shared_mutex> gate(c->committed_read_gate);
    std::lock_guard<std::mutex> metadata(c->metadata_mutex);
    const auto id = o->node->object_id;
    const auto attribute = c->metadata_store->LookupWorkingExtendedAttribute(id, o->native_xattr_name);
    if (!attribute)
    {
        // A snapshot is captured immediately before native unlink/replacement,
        // never hydrated at Open. It belongs to the retained inode identity.
        if (!o->native_xattr->unlinked_value || c->metadata_store->LookupCommittedInodeByObjectId(id))
            return STATUS_OBJECT_NAME_NOT_FOUND;
        const auto& retained = *o->native_xattr->unlinked_value;
        size = retained.size();
        const auto count = offset >= size ? 0 : (std::min<std::uint64_t>)(length, size - offset);
        if (count) bytes.assign(retained.begin() + static_cast<std::size_t>(offset),
            retained.begin() + static_cast<std::size_t>(offset + count));
        return STATUS_SUCCESS;
    }
    if (attribute->object_id != id || attribute->name_utf8 != o->native_xattr_name) return STATUS_IO_DEVICE_ERROR;
    const auto storage = attribute->flags & (apfsaccess::rw::kAppleXattrDataEmbedded | apfsaccess::rw::kAppleXattrDataStream);
    if (attribute->flags & ~(apfsaccess::rw::kAppleXattrDataEmbedded |
            apfsaccess::rw::kAppleXattrDataStream | apfsaccess::rw::kAppleXattrFileSystemOwned)) return STATUS_NOT_SUPPORTED;
    if (storage == apfsaccess::rw::kAppleXattrDataEmbedded) size = attribute->data.size();
    else if (storage == apfsaccess::rw::kAppleXattrDataStream &&
        attribute->data.size() == apfsaccess::rw::kAppleXattrDataStreamBytes)
        size = apfsaccess::catalog::ReadU64LE(attribute->data, 8).value_or(UINT64_MAX);
    else return STATUS_NOT_SUPPORTED;
    if (size > static_cast<std::uint64_t>(INT64_MAX) - 4095) return STATUS_NOT_SUPPORTED;
    const auto count = offset >= size ? 0 : (std::min<std::uint64_t>)(length, size - offset);
    bytes.resize(static_cast<std::size_t>(count));
    const auto committed = c->metadata_store->LookupCommittedExtendedAttribute(id, o->native_xattr_name);
    // Only pending inline replacements bypass the committed range validator.
    if (storage == apfsaccess::rw::kAppleXattrDataEmbedded &&
        (!committed || committed->flags != attribute->flags || committed->data != attribute->data))
    {
        if (count) std::copy_n(attribute->data.begin() + static_cast<std::size_t>(offset),
            static_cast<std::size_t>(count), bytes.begin());
    }
    else
    {
        std::size_t actual = 0;
        if (!c->metadata_store->ReadCommittedExtendedAttributeRange(id, o->native_xattr_name,
                offset, bytes, actual) || actual != count)
        { bytes.clear(); return STATUS_IO_DEVICE_ERROR; }
    }
    return STATUS_SUCCESS;
#else
    return STATUS_NOT_SUPPORTED;
#endif
}

NTSTATUS CaptureNativeXattrsBeforeUnlink(MountContext* c, const std::wstring& path)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!c) return STATUS_INVALID_PARAMETER;
    if (c->native_xattr_streams.empty()) return STATUS_SUCCESS;
    if (!c->metadata_store)
    {
        for (const auto& [key, weak] : c->native_xattr_streams)
            if (const auto state = weak.lock(); state && !state->removed && !state->protocol)
                return STATUS_IO_DEVICE_ERROR;
        return STATUS_SUCCESS;
    }
    try
    {
        std::uint64_t id = 0;
        {
            std::lock_guard<std::mutex> metadata(c->metadata_mutex);
            if (auto inode = c->metadata_store->LookupWorkingInodeByPath(path)) id = inode->object_id;
        }
        if (!id) return STATUS_SUCCESS;
        for (const auto& [key, weak] : c->native_xattr_streams)
        {
            if (key.first != id) continue;
            const auto state = weak.lock();
            if (!state || state->removed || state->protocol) continue;
            OpenContext probe;
            probe.node = std::make_shared<Node>(); probe.node->object_id = id;
            probe.native_xattr = state; probe.native_xattr_name = key.second;
            std::vector<std::byte> bytes; std::uint64_t size = 0;
            constexpr auto limit = apfsaccess::rw::WriteAheadLog::MaxExtendedAttributePayloadBytes;
            // Preparation must run before WAL acceptance, namespace changes, or
            // delete intent. Large external values remain readable while linked;
            // refuse their unlink instead of allocating an unbounded snapshot.
            auto status = NativeXattrValue(c, &probe, 0, 0, bytes, size);
            if (!NT_SUCCESS(status)) return status;
            if (size > limit) return STATUS_SHARING_VIOLATION;
            status = NativeXattrValue(c, &probe, 0, static_cast<std::size_t>(size), bytes, size);
            if (!NT_SUCCESS(status)) return status;
            if (size > limit) return STATUS_SHARING_VIOLATION;
            if (bytes.size() != size) return STATUS_IO_DEVICE_ERROR;
            // Publish only a complete capture. A failed read/allocation leaves the
            // old usable snapshot intact; earlier complete captures remain usable.
            state->unlinked_value = std::move(bytes);
        }
    }
    catch (const std::bad_alloc&)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
#else
    (void)c; (void)path;
#endif
    return STATUS_SUCCESS;
}

NTSTATUS NativeXattrInfo(MountContext* c, OpenContext* o, FSP_FSCTL_FILE_INFO* info)
{
    std::vector<std::byte> ignored;
    std::uint64_t size = 0;
    const auto status = NativeXattrValue(c, o, 0, 0, ignored, size);
    if (!NT_SUCCESS(status)) return status;
    std::lock_guard<std::mutex> lock(c->mutex);
    o->stream_size = size;
    if (info)
    {
        FillInfo(*o->node, ReportsReadOnly(c), info);
        info->FileAttributes &= ~FILE_ATTRIBUTE_DIRECTORY;
        info->FileSize = size;
        info->AllocationSize = ((size + 4095) / 4096) * 4096;
    }
    return STATUS_SUCCESS;
}

NTSTATUS ValidateNativeXattrEdit(MountContext* c, OpenContext* o, std::wstring& path)
{
    if (o && o->native_xattr && o->native_xattr->protocol) return STATUS_ACCESS_DENIED;
    if (!IsMutationWriteEnabled(c)) return STATUS_MEDIA_WRITE_PROTECTED;
    if (!o || !o->native_xattr || !o->node) return STATUS_INVALID_HANDLE;
    const auto& name = o->native_xattr_name;
    if (name.starts_with("com.apfsaccess.windows.") || name == "com.apple.system.Security") return STATUS_ACCESS_DENIED;
    if (name == "com.apple.decmpfs" || name.starts_with("com.apple.fs.")) return STATUS_NOT_SUPPORTED;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (VisibleWindowsAttributes(*o->node) & FILE_ATTRIBUTE_READONLY) return STATUS_ACCESS_DENIED;
    }
    path = SnapshotMutationPathForNode(c, *o->node);
    if (path.empty()) return STATUS_FILE_DELETED;
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!IsNativeWriteEnabled(c) || !c->metadata_store || !c->tx_manager) return STATUS_NOT_SUPPORTED;
    std::lock_guard<std::mutex> metadata(c->metadata_mutex);
    const auto inode = c->metadata_store->LookupWorkingInodeByPath(path);
    if (!inode || inode->object_id != o->node->object_id) return STATUS_FILE_DELETED;
    if (!c->metadata_store->AuthoritativeAppleCheckpointView()) return STATUS_NOT_SUPPORTED;
    const auto committed = c->metadata_store->LookupCommittedInodeByObjectId(inode->object_id);
    // The engine currently refuses all independent xattr edits on compressed
    // owners. Match that admission before arming a recovery marker or WAL.
    if ((inode->bsd_flags & apfsaccess::rw::kAppleBsdCompressedFlag) ||
        (committed && (committed->bsd_flags & apfsaccess::rw::kAppleBsdCompressedFlag)) ||
        c->metadata_store->LookupWorkingExtendedAttribute(inode->object_id, "com.apple.decmpfs") ||
        c->metadata_store->LookupCommittedExtendedAttribute(inode->object_id, "com.apple.decmpfs")) return STATUS_NOT_SUPPORTED;
    const auto previous = c->metadata_store->LookupWorkingExtendedAttribute(inode->object_id, name);
    if (previous && previous->flags != apfsaccess::rw::kAppleXattrDataEmbedded &&
        previous->flags != apfsaccess::rw::kAppleXattrDataStream) return STATUS_NOT_SUPPORTED;
    if (name == "com.apple.ResourceFork" &&
        (!apfsaccess::rw::IsUncompressedAppleResourceForkOwner(inode->object_id, inode->private_id,
            inode->mode, inode->bsd_flags, false) ||
         (committed && !apfsaccess::rw::IsUncompressedAppleResourceForkOwner(committed->object_id,
            committed->private_id, committed->mode, committed->bsd_flags, false)))) return STATUS_NOT_SUPPORTED;
    return STATUS_SUCCESS;
#else
    return STATUS_NOT_SUPPORTED;
#endif
}

NTSTATUS MutateNativeXattr(MountContext* c, OpenContext* o, std::span<const std::byte> value,
    bool remove, FSP_FSCTL_FILE_INFO* info = nullptr)
{
    std::wstring path;
    auto status = ValidateNativeXattrEdit(c, o, path);
    if (!NT_SUCCESS(status)) return status;
#ifdef APFSACCESS_HAS_RW_ENGINE
    using Store = apfsaccess::rw::MetadataStore;
    using Kind = apfsaccess::rw::TransactionManager::MutationKind;
    constexpr auto limit = apfsaccess::rw::WriteAheadLog::MaxExtendedAttributePayloadBytes;
    if (value.size() > limit) return STATUS_NOT_SUPPORTED;
    // Read the entire preimage before any staging, including external extents.
    std::vector<std::byte> previous;
    std::uint64_t previous_size = 0;
    status = NativeXattrValue(c, o, 0, limit + 1, previous, previous_size);
    if (status != STATUS_OBJECT_NAME_NOT_FOUND && !NT_SUCCESS(status)) return status;
    if (previous_size > limit) return STATUS_NOT_SUPPORTED;
    if (remove && status == STATUS_OBJECT_NAME_NOT_FOUND) return status;
    Store::PayloadIdentity identity{};
    bool staged = false;
    const auto wide_name = Utf8ToWide(o->native_xattr_name);
    std::size_t batch = 0;
    if (IsManifestSession(c)) batch = ManifestQueuedRequestCount(c) + 1;
    else { std::lock_guard<std::mutex> lock(c->metadata_mutex); batch = c->metadata_store->PendingMutationCount() + 1; }
    const bool recorded = RecordNativeMutationBestEffort(c,
        remove ? Store::MutationOperation::RemoveExtendedAttribute : Store::MutationOperation::SetExtendedAttribute,
        path, wide_name, 0, value.size(), false, 0, &identity, &staged, nullptr, batch, value) &&
        RecordMutationBestEffort(c, remove ? Kind::RemoveExtendedAttribute : Kind::SetExtendedAttribute,
            path, wide_name, 0, value.size(), false, 0, 0, &identity, nullptr, value);
    if (!recorded) return BlockNativeMutationAfterStagingFailure(c, L"NativeXattr", staged);
    status = DrainNativeMutationsByPolicy(c, L"NativeXattr", false, true);
    if (!NT_SUCCESS(status)) return status;
    if (!FinalizeMutationJournalBestEffort(c, L"NativeXattr")) return STATUS_UNSUCCESSFUL;
    o->native_xattr->removed = remove;
    o->native_xattr->unlinked_value.reset();
    o->native_xattr->removed_value = remove ? std::move(previous) : std::vector<std::byte>{};
    MarkOpenContextMutation(o);
    return NativeXattrInfo(c, o, info);
#else
    return STATUS_NOT_SUPPORTED;
#endif
}

NTSTATUS NativeXattrSetDelete(MountContext* c, OpenContext* o, bool deleting)
{
    if (!o->allow_delete) return STATUS_ACCESS_DENIED;
    if (deleting && o->native_xattr->removed && !o->stream_delete_pending) return STATUS_DELETE_PENDING;
    if (deleting == o->stream_delete_pending) { o->stream_delete_cancelled = !deleting; return STATUS_SUCCESS; }
    if (!deleting && !o->native_xattr->removed) return STATUS_FILE_DELETED;
    const auto retained = o->native_xattr->removed_value;
    const auto status = MutateNativeXattr(c, o, deleting ? std::span<const std::byte>{} : std::span<const std::byte>(retained), deleting);
    if (NT_SUCCESS(status)) { o->stream_delete_pending = deleting; o->stream_delete_cancelled = !deleting; }
    else if (deleting && !o->stream_delete_pending) o->stream_delete_cancelled = true;
    return status;
}

NTSTATUS OpenNativeXattr(MountContext* c, const NamedStreamPath& stream, UINT32 options,
    UINT32 access, bool create, UINT64 allocation, PVOID* result, FSP_FSCTL_FILE_INFO* info)
{
    std::string name;
    if (DecodeNativeXattrStream(stream.stream_name, name) != 1) return STATUS_OBJECT_NAME_INVALID;
    auto node = FindNodeNormalized(c, stream.base_path);
    if (!node) return STATUS_OBJECT_NAME_NOT_FOUND;
    if ((!node->is_directory && node->node_kind != NodeKind::RegularFile) || (options & FILE_DIRECTORY_FILE)) return STATUS_NOT_SUPPORTED;
    if (IsDeleteBlockedStateLocked(node)) return STATUS_DELETE_PENDING;
    auto o = std::make_unique<OpenContext>();
    o->node = node; o->named_stream = true; o->stream_name = NativeXattrStreamName(name); o->native_xattr_name = name;
    InitializeOpenAccess(o.get(), access);
    if (name.empty())
    {
#ifdef APFSACCESS_HAS_RW_ENGINE
        if (!c->metadata_store) return STATUS_NOT_SUPPORTED;
        {
            std::lock_guard<std::mutex> metadata(c->metadata_mutex);
            if (!c->metadata_store->AuthoritativeAppleCheckpointView()) return STATUS_NOT_SUPPORTED;
        }
        if (create || ((options >> 24) & 0xff) != FILE_OPEN || HasOpenMutationIntent(access, options) ||
            (NormalizeGrantedAccess(access) & (WRITE_DAC | WRITE_OWNER | DELETE))) return STATUS_ACCESS_DENIED;
        o->stream_name = L":APFS.XattrProtocol:$DATA";
        o->native_xattr = std::make_shared<NativeXattrStreamState>();
        o->native_xattr->protocol = true;
        const auto status = NativeXattrInfo(c, o.get(), info);
        if (!NT_SUCCESS(status)) return status;
        { std::lock_guard<std::mutex> lock(c->mutex); AcquireOpenContextAccountingLocked(c, node, o.get()); }
        *result = o.release();
        return STATUS_SUCCESS;
#else
        return STATUS_NOT_SUPPORTED;
#endif
    }
    const auto disposition = (options >> 24) & 0xff;
    if (disposition == FILE_SUPERSEDE || disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF)
        o->pending_overwrite_supersede = disposition == FILE_SUPERSEDE;
    if (HasOpenMutationIntent(access, options) && !IsMutationWriteEnabled(c)) return STATUS_MEDIA_WRITE_PROTECTED;
    auto& weak = c->native_xattr_streams[{node->object_id, name}];
    o->native_xattr = weak.lock();
    if (o->native_xattr && o->native_xattr->removed) return STATUS_DELETE_PENDING;
    if (!o->native_xattr) { o->native_xattr = std::make_shared<NativeXattrStreamState>(); weak = o->native_xattr; }
    if ((options & FILE_DELETE_ON_CLOSE) && !o->allow_delete) return STATUS_ACCESS_DENIED;
    if (create || (options & FILE_DELETE_ON_CLOSE))
    {
        std::wstring path;
        const auto eligible = ValidateNativeXattrEdit(c, o.get(), path);
        if (!NT_SUCCESS(eligible)) return eligible;
    }
    auto status = NativeXattrInfo(c, o.get(), info);
    if (create)
    {
        if (NT_SUCCESS(status)) return STATUS_OBJECT_NAME_COLLISION;
        if (status != STATUS_OBJECT_NAME_NOT_FOUND) return status;
        if (!o->allow_write_data && !o->allow_append_data) return STATUS_ACCESS_DENIED;
#ifdef APFSACCESS_HAS_RW_ENGINE
        if (allocation > apfsaccess::rw::WriteAheadLog::MaxExtendedAttributePayloadBytes) return STATUS_NOT_SUPPORTED;
#endif
        status = MutateNativeXattr(c, o.get(), {}, false, info);
    }
    if (!NT_SUCCESS(status)) return status;
    if (options & FILE_DELETE_ON_CLOSE)
    {
        status = NativeXattrSetDelete(c, o.get(), true);
        if (!NT_SUCCESS(status)) return status;
    }
    { std::lock_guard<std::mutex> lock(c->mutex); AcquireOpenContextAccountingLocked(c, node, o.get()); }
    *result = o.release();
    return STATUS_SUCCESS;
}

NTSTATUS WriteNativeXattr(MountContext* c, OpenContext* o, PVOID buffer, UINT64 offset,
    ULONG length, BOOLEAN append, BOOLEAN constrained, PULONG done, FSP_FSCTL_FILE_INFO* info,
    bool resize = false, bool allocation = false)
{
    if (o->native_xattr->removed) return STATUS_DELETE_PENDING;
    std::wstring path;
    auto status = ValidateNativeXattrEdit(c, o, path);
    if (!NT_SUCCESS(status)) return status;
#ifdef APFSACCESS_HAS_RW_ENGINE
    constexpr auto limit = apfsaccess::rw::WriteAheadLog::MaxExtendedAttributePayloadBytes;
    std::vector<std::byte> value;
    std::uint64_t size = 0;
    status = NativeXattrValue(c, o, 0, limit + 1, value, size);
    if (!NT_SUCCESS(status)) return status;
    if (size > limit) return STATUS_NOT_SUPPORTED;
    if (append) offset = size;
    if (resize)
    {
        if (offset > limit) return STATUS_NOT_SUPPORTED;
        value.resize(static_cast<std::size_t>(allocation ? (std::min)(offset, size) : offset));
    }
    else
    {
        if (!o->allow_write_data && !append) return STATUS_ACCESS_DENIED;
        if (constrained) length = offset >= size ? 0 : static_cast<ULONG>((std::min<std::uint64_t>)(length, size - offset));
        if (!length) return NativeXattrInfo(c, o, info);
        if (offset > limit || length > limit - offset) return STATUS_NOT_SUPPORTED;
        value.resize(static_cast<std::size_t>((std::max)(size, offset + length)));
        std::memcpy(value.data() + offset, buffer, length);
    }
    status = MutateNativeXattr(c, o, value, false, info);
    if (NT_SUCCESS(status) && done) *done = length;
    return status;
#else
    return STATUS_NOT_SUPPORTED;
#endif
}
