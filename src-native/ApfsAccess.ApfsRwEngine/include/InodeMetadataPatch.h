#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace apfsaccess::rw
{
struct InodeMetadataPatch
{
    enum Field : std::uint32_t
    {
        Owner = 1, Group = 2, Mode = 4, CreateTime = 8,
        ModificationTime = 16, ChangeTime = 32, AccessTime = 64,
        BsdFlags = 128,
    };
    static constexpr std::uint64_t UnixEpochTicks = 116444736000000000ULL;
    static constexpr std::uint32_t KnownFields = 255;
    static constexpr std::size_t EncodedSize = 52;
    static constexpr std::size_t BsdEncodedSize = 56;
    static constexpr std::uint64_t MaxTime =
        UnixEpochTicks + (std::numeric_limits<std::uint64_t>::max)() / 100;

    std::uint32_t mask = 0, owner = 0, group = 0, bsd_flags = 0;
    std::uint16_t mode = 0;
    std::uint64_t create_time_utc = 0, modification_time_utc = 0;
    std::uint64_t change_time_utc = 0, access_time_utc = 0;
};

inline bool EncodeInodeMetadataPatch(const InodeMetadataPatch& patch, std::vector<std::byte>& output)
{
    output.clear();
    const auto time_valid = [&](InodeMetadataPatch::Field field, std::uint64_t value)
    {
        return (patch.mask & field) != 0
            ? value >= InodeMetadataPatch::UnixEpochTicks && value <= InodeMetadataPatch::MaxTime
            : value == 0;
    };
    if (patch.mask == 0 || (patch.mask & ~InodeMetadataPatch::KnownFields) != 0 ||
        (!(patch.mask & InodeMetadataPatch::Owner) && patch.owner != 0) ||
        (!(patch.mask & InodeMetadataPatch::Group) && patch.group != 0) ||
        (!(patch.mask & InodeMetadataPatch::Mode) && patch.mode != 0) || patch.mode > 07777 ||
        (!(patch.mask & InodeMetadataPatch::BsdFlags) && patch.bsd_flags != 0) ||
        !time_valid(InodeMetadataPatch::CreateTime, patch.create_time_utc) ||
        !time_valid(InodeMetadataPatch::ModificationTime, patch.modification_time_utc) ||
        !time_valid(InodeMetadataPatch::ChangeTime, patch.change_time_utc) ||
        !time_valid(InodeMetadataPatch::AccessTime, patch.access_time_utc))
    {
        return false;
    }
    const bool has_bsd_flags = (patch.mask & InodeMetadataPatch::BsdFlags) != 0;
    output.assign(has_bsd_flags
            ? InodeMetadataPatch::BsdEncodedSize
            : InodeMetadataPatch::EncodedSize,
        std::byte{0});
    output[0] = std::byte{'I'};
    output[1] = std::byte{'M'};
    output[2] = std::byte{'D'};
    output[3] = has_bsd_flags ? std::byte{2} : std::byte{1};
    const auto put = [&](std::size_t offset, std::uint64_t value, std::size_t count)
    {
        for (std::size_t i = 0; i < count; ++i)
            output[offset + i] = static_cast<std::byte>((value >> (8 * i)) & 0xff);
    };
    put(4, patch.mask, 4);
    put(8, patch.owner, 4);
    put(12, patch.group, 4);
    put(16, patch.mode, 2);
    put(20, patch.create_time_utc, 8);
    put(28, patch.modification_time_utc, 8);
    put(36, patch.change_time_utc, 8);
    put(44, patch.access_time_utc, 8);
    if (has_bsd_flags) put(52, patch.bsd_flags, 4);
    return true;
}

inline bool DecodeInodeMetadataPatch(std::span<const std::byte> bytes, InodeMetadataPatch& output)
{
    output = {};
    if ((bytes.size() != InodeMetadataPatch::EncodedSize &&
            bytes.size() != InodeMetadataPatch::BsdEncodedSize) ||
        bytes[0] != std::byte{'I'} || bytes[1] != std::byte{'M'} ||
        bytes[2] != std::byte{'D'} ||
        bytes[18] != std::byte{0} || bytes[19] != std::byte{0})
        return false;
    const bool is_v1 = bytes[3] == std::byte{1} &&
        bytes.size() == InodeMetadataPatch::EncodedSize;
    const bool is_v2 = bytes[3] == std::byte{2} &&
        bytes.size() == InodeMetadataPatch::BsdEncodedSize;
    if (!is_v1 && !is_v2) return false;
    const auto get = [&](std::size_t offset, std::size_t count)
    {
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < count; ++i)
            value |= std::uint64_t{std::to_integer<unsigned char>(bytes[offset + i])} << (8 * i);
        return value;
    };
    InodeMetadataPatch patch{};
    patch.mask = static_cast<std::uint32_t>(get(4, 4));
    patch.owner = static_cast<std::uint32_t>(get(8, 4));
    patch.group = static_cast<std::uint32_t>(get(12, 4));
    patch.mode = static_cast<std::uint16_t>(get(16, 2));
    patch.create_time_utc = get(20, 8);
    patch.modification_time_utc = get(28, 8);
    patch.change_time_utc = get(36, 8);
    patch.access_time_utc = get(44, 8);
    if (is_v2) patch.bsd_flags = static_cast<std::uint32_t>(get(52, 4));
    std::vector<std::byte> canonical;
    if (!EncodeInodeMetadataPatch(patch, canonical) || canonical.size() != bytes.size()) return false;
    for (std::size_t i = 0; i < bytes.size(); ++i)
        if (canonical[i] != bytes[i]) return false;
    output = patch;
    return true;
}
}
