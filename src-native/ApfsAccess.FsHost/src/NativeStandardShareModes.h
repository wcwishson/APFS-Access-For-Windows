#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <windows.h>

namespace apfsaccess::fshost::standard_mount
{
struct ShareOpen
{
    std::uint64_t inode = 0;
    std::wstring_view stream;
    std::uint32_t access = 0;
    std::uint32_t share = 0;
};

enum class ShareAdmission { Allowed, InvalidParameter, SharingViolation };

inline ShareAdmission CheckShareAdmission(const ShareOpen& requested,
    std::span<const ShareOpen> existing) noexcept
{
    constexpr std::uint32_t share_mask = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    constexpr std::uint32_t generic_mask = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL;
    if (!requested.inode || (requested.share & ~share_mask) || (requested.access & generic_mask) ||
        (requested.access & MAXIMUM_ALLOWED)) return ShareAdmission::InvalidParameter;

    const auto reads = [](const ShareOpen& open) { return (open.access & (FILE_READ_DATA | FILE_EXECUTE)) != 0; };
    const auto writes = [](const ShareOpen& open) { return (open.access & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0; };
    const auto deletes = [](const ShareOpen& open) { return (open.access & DELETE) != 0; };
    const auto participates = [&](const ShareOpen& open) { return reads(open) || writes(open) || deletes(open); };
    if (!participates(requested)) return ShareAdmission::Allowed;

    for (const auto& held : existing)
    {
        if (held.inode != requested.inode) continue;
        if ((held.share & ~share_mask) || (held.access & (generic_mask | MAXIMUM_ALLOWED)))
            return ShareAdmission::InvalidParameter;
        if (!participates(held)) continue;
        // Data sharing is per stream; deleting an inode checks all its streams.
        if ((deletes(requested) && !(held.share & FILE_SHARE_DELETE)) ||
            (deletes(held) && !(requested.share & FILE_SHARE_DELETE)))
            return ShareAdmission::SharingViolation;
        if (held.stream != requested.stream) continue;
        if ((reads(requested) && !(held.share & FILE_SHARE_READ)) ||
            (writes(requested) && !(held.share & FILE_SHARE_WRITE)) ||
            (reads(held) && !(requested.share & FILE_SHARE_READ)) ||
            (writes(held) && !(requested.share & FILE_SHARE_WRITE)))
            return ShareAdmission::SharingViolation;
    }
    return ShareAdmission::Allowed;
}
}
