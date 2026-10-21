#pragma once
#include "NativeStandardProtocol.h"
#ifndef APFSACCESS_ENABLE_STANDARD_SPARSE
#define APFSACCESS_ENABLE_STANDARD_SPARSE 0
#endif
#ifndef APFSACCESS_ENABLE_STANDARD_HARDLINK
#define APFSACCESS_ENABLE_STANDARD_HARDLINK 0
#endif
#ifndef APFSACCESS_ENABLE_STANDARD_CLONE_RANGE
#define APFSACCESS_ENABLE_STANDARD_CLONE_RANGE 0
#endif
#if APFSACCESS_ENABLE_STANDARD_SPARSE
#include "NativeSparsePlan.h"
#endif
namespace native_standard
{
using Bytes = std::vector<std::byte>;
std::uint64_t Features(MountContext& context)
{
    std::uint64_t result = 7;
#if APFSACCESS_ENABLE_STANDARD_SPARSE || APFSACCESS_ENABLE_STANDARD_HARDLINK || APFSACCESS_ENABLE_STANDARD_CLONE_RANGE
    std::lock_guard metadata(context.metadata_mutex);
#endif
#if APFSACCESS_ENABLE_STANDARD_SPARSE
    apfsaccess::rw::BlockDevice::StableImageIdentity image;
    const auto* view = context.metadata_store->AuthoritativeAppleCheckpointView();
    if (view && view->volumes.size() == 1 && view->container.superblock.block_size == 4096 &&
        !context.metadata_store->Device().BaseOffsetBytes() &&
        context.metadata_store->Device().QueryHeldImageIdentity(image) && image.size_bytes <= apfsaccess::rw::NativeSparseMaxImageBytes)
        result |= 8;
#endif
#if APFSACCESS_ENABLE_STANDARD_HARDLINK || APFSACCESS_ENABLE_STANDARD_CLONE_RANGE
    const auto* hardlink_view = context.metadata_store->AuthoritativeAppleCheckpointView();
    apfsaccess::rw::BlockDevice::StableImageIdentity hardlink_image;
    if (hardlink_view && hardlink_view->volumes.size() == 1 && hardlink_view->container.superblock.block_size == 4096 &&
        !context.metadata_store->Device().BaseOffsetBytes() &&
        context.metadata_store->Device().QueryHeldImageIdentity(hardlink_image))
    {
#if APFSACCESS_ENABLE_STANDARD_HARDLINK
        result |= 32;
#endif
#if APFSACCESS_ENABLE_STANDARD_CLONE_RANGE
        result |= 16;
#endif
    }
#endif
    const auto names = apfsaccess::rw::ApfsNamePolicy::FromIncompatibleFeatures(context.args.incompatible_features);
    return result | (names.case_mode == apfsaccess::rw::ApfsCaseMode::Sensitive ? 64u : 0u);
}
void OverlaySparseAttributes(MountContext& context, FSP_FSCTL_FILE_INFO& info)
{
#if APFSACCESS_ENABLE_STANDARD_SPARSE
    std::lock_guard metadata(context.metadata_mutex);
    const auto inode = context.metadata_store->LookupCommittedInodeByObjectId(info.IndexNumber);
    if (inode && !inode->is_directory)
    {
        info.FileAttributes &= ~FILE_ATTRIBUTE_SPARSE_FILE;
        if (inode->internal_flags & apfsaccess::rw::kAppleInodeSparseFlag) info.FileAttributes |= FILE_ATTRIBUTE_SPARSE_FILE;
    }
#else
    (void)context; (void)info;
#endif
}
void Number(Bytes& out, std::uint64_t value, std::size_t count)
{
    const auto offset = out.size();
    out.resize(offset + count);
    apfsaccess::fshost::standard_mount::PutLittle(std::span(out).subspan(offset, count), value);
}
void Text(Bytes& out, std::wstring_view value)
{
    Number(out, value.size(), 4);
    for (const auto ch : value) Number(out, static_cast<std::uint16_t>(ch), 2);
}
void Basic(Bytes& out, const FSP_FSCTL_FILE_INFO& info)
{
    for (const auto value : {info.CreationTime, info.LastAccessTime, info.LastWriteTime, info.ChangeTime}) Number(out, value, 8);
    Number(out, info.FileAttributes, 4); Number(out, 0, 4);
}
void Standard(Bytes& out, const FSP_FSCTL_FILE_INFO& info, std::uint32_t links, bool pending)
{
    Number(out, info.AllocationSize, 8); Number(out, info.FileSize, 8); Number(out, links, 4);
    Number(out, pending ? 1 : 0, 1); Number(out, (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0, 1);
    Number(out, 0, 2);
}
NTSTATUS FileInformation(MountContext& context, OpenContext& open, const FSP_FSCTL_FILE_INFO& original,
    std::uint32_t information_class, std::uint64_t position, std::uint32_t options, Bytes& result)
{
    auto info = original;
    OverlaySparseAttributes(context, info);
    std::wstring name;
    bool pending = false;
    {
        std::lock_guard names(context.mutex);
        if (!open.node) return STATUS_INVALID_HANDLE;
        name = open.node->path + open.stream_name;
        pending = open.delete_on_cleanup || open.delete_on_close_requested || open.node->namespace_detached;
    }
    std::uint32_t links = 0;
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (information_class == 5 || information_class == 18)
    {
        std::lock_guard metadata(context.metadata_mutex);
        const auto inode = context.metadata_store ? context.metadata_store->LookupWorkingInodeByPath(open.node->path) : std::nullopt;
        if (!inode || inode->object_id != open.node->object_id) return STATUS_NOT_SUPPORTED;
        links = inode->is_directory ? 1u : inode->link_count;
    }
#endif
    const auto append_name = [&] {
        Number(result, name.size() * 2, 4);
        for (const auto ch : name) Number(result, static_cast<std::uint16_t>(ch), 2);
    };
    switch (information_class)
    {
    case 4: Basic(result, info); break;
    case 5: Standard(result, info, links, pending); break;
    case 6: Number(result, info.IndexNumber, 8); break;
    case 7: Number(result, 0, 4); break; // APFS xattrs are streams, not NT extended attributes.
    case 8: Number(result, open.granted_access, 4); break;
    case 9: append_name(); break;
    case 14: Number(result, position, 8); break;
    case 16: Number(result, options, 4); break;
    case 17: Number(result, 0, 4); break;
    case 18:
        Basic(result, info); Standard(result, info, links, pending); Number(result, info.IndexNumber, 8);
        Number(result, 0, 4); Number(result, open.granted_access, 4); Number(result, position, 8);
        Number(result, options, 4); Number(result, 0, 4); append_name(); break;
    case 34:
        Basic(result, info);
        result.resize(32);
        Number(result, info.AllocationSize, 8); Number(result, info.FileSize, 8);
        Number(result, info.FileAttributes, 4); Number(result, 0, 4); break;
    case 35: Number(result, info.FileAttributes, 4); Number(result, info.ReparseTag, 4); break;
    default: return STATUS_INVALID_INFO_CLASS;
    }
    return STATUS_SUCCESS;
}

NTSTATUS VolumeInformation(MountContext& context, std::uint32_t information_class, Bytes& out)
{
    const auto reported = CaptureReportedVolumeInfo(context);
    const auto unit = reported.allocation_unit_bytes;
    if (!unit || unit > UINT32_MAX || unit % 512 || !reported.total_size_bytes || !reported.free_size_bytes)
        return STATUS_NOT_SUPPORTED;
    std::wstring label;
    { std::lock_guard lock(context.volume_label_mutex); label = context.label; }
    switch (information_class)
    {
    case 1:
        Number(out, 0, 8); Number(out, BuildStableVolumeSerial(context.args), 4); Number(out, label.size() * 2, 4);
        Number(out, 0, 1); Number(out, 0, 1);
        for (auto ch : label) Number(out, static_cast<std::uint16_t>(ch), 2);
        break;
    case 3:
    case 7:
        Number(out, *reported.total_size_bytes / unit, 8); Number(out, *reported.free_size_bytes / unit, 8);
        if (information_class == 7) Number(out, *reported.free_size_bytes / unit, 8);
        Number(out, unit / 512, 4); Number(out, 512, 4); break;
    case 4:
        Number(out, FILE_DEVICE_DISK, 4); Number(out, 0x00000010u, 4); break; // FILE_REMOTE_DEVICE from MS-FSCC.
    case 5:
    {
        const auto names = apfsaccess::rw::ApfsNamePolicy::FromIncompatibleFeatures(context.args.incompatible_features);
        Number(out, FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK | FILE_PERSISTENT_ACLS |
            ((Features(context) & 8) ? FILE_SUPPORTS_SPARSE_FILES : 0) |
            ((Features(context) & 32) ? FILE_SUPPORTS_HARD_LINKS : 0) |
            ((Features(context) & 16) ? FILE_SUPPORTS_BLOCK_REFCOUNTING : 0) |
            (names.case_mode == apfsaccess::rw::ApfsCaseMode::Sensitive ? FILE_CASE_SENSITIVE_SEARCH : 0), 4);
        Number(out, 255, 4); Number(out, 8, 4);
        for (const auto ch : std::wstring_view(L"APFS")) Number(out, static_cast<std::uint16_t>(ch), 2);
        break;
    }
    default: return STATUS_INVALID_INFO_CLASS;
    }
    return STATUS_SUCCESS;
}
}
