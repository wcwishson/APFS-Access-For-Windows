#pragma once

#include "ApfsFormat.h"
#include <algorithm>
#include <span>
#include <string_view>

namespace apfsaccess::rw
{
// VRN1 is a bounded typed payload in the existing inline-payload WAL envelope.
// Labels are values, never selectors. The complete APSB binds role, limits and
// all recovery/tree owners to the same preimage as the stable UUID/OID tuple.
struct NativeVolumeRename
{
    bool quota_reserve = false;
    std::uint64_t quota_blocks = 0, reserve_blocks = 0;
    std::string image_identity;
    std::string space_census_sha256;
    std::uint64_t checkpoint = 0;
    std::uint64_t volume = 0;
    std::string container_uuid;
    std::string volume_uuid;
    std::string old_label;
    std::string new_label;
    std::vector<std::byte> superblock;
};

inline bool ValidNativeVolumeLabel(std::string_view text)
{
    if (text.empty() || text.size() > 255) return false;
    for (std::size_t i = 0; i < text.size();)
    {
        const auto lead = static_cast<unsigned char>(text[i++]);
        if (!lead) return false;
        if (lead < 0x80) continue;
        unsigned count = 0, code = 0, minimum = 0;
        if (lead >= 0xc2 && lead <= 0xdf) { count = 1; code = lead & 31; minimum = 0x80; }
        else if (lead >= 0xe0 && lead <= 0xef) { count = 2; code = lead & 15; minimum = 0x800; }
        else if (lead >= 0xf0 && lead <= 0xf4) { count = 3; code = lead & 7; minimum = 0x10000; }
        else return false;
        if (count > text.size() - i) return false;
        while (count--)
        {
            const auto ch = static_cast<unsigned char>(text[i++]);
            if ((ch & 0xc0) != 0x80) return false;
            code = (code << 6) | (ch & 63);
        }
        if (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return false;
    }
    return true;
}

inline bool ValidRenameUuid(std::string_view uuid)
{
    return uuid.size() == 32 && uuid.find_first_not_of('0') != std::string_view::npos &&
        std::all_of(uuid.begin(), uuid.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        });
}

inline std::vector<std::byte> EncodeNativeVolumeRename(const NativeVolumeRename& value)
{
    std::vector<std::byte> bytes;
    const auto put = [&](std::uint64_t n) {
        for (unsigned i = 0; i != 8; ++i) bytes.push_back(std::byte((n >> (8 * i)) & 255));
    };
    put(value.quota_reserve ? 0x31535251 : 0x314e5256); put(value.checkpoint); put(value.volume);
    if (value.quota_reserve) {
        put(value.quota_blocks); put(value.reserve_blocks); put(value.image_identity.size());
        for (unsigned char c : value.image_identity) bytes.push_back(std::byte(c));
        put(value.space_census_sha256.size());
        for (unsigned char c : value.space_census_sha256) bytes.push_back(std::byte(c));
    }
    for (const auto* s : {&value.container_uuid, &value.volume_uuid, &value.old_label, &value.new_label})
    {
        put(s->size());
        for (unsigned char c : *s) bytes.push_back(std::byte(c));
    }
    put(value.superblock.size());
    bytes.insert(bytes.end(), value.superblock.begin(), value.superblock.end());
    return bytes;
}

inline bool DecodeNativeVolumeMetadata(std::span<const std::byte> bytes, NativeVolumeRename& out)
{
    if (bytes.size() < 128 || bytes.size() > 67000) return false;
    std::size_t at = 0;
    bool valid = true;
    const auto get = [&]() {
        std::uint64_t n = 0;
        if (bytes.size() - at < 8) { valid = false; return n; }
        for (unsigned i = 0; i != 8; ++i) n |= std::uint64_t(std::to_integer<unsigned char>(bytes[at++])) << (8 * i);
        return n;
    };
    const auto magic = get();
    if (magic != 0x314e5256 && magic != 0x31535251) return false;
    NativeVolumeRename value;
    value.quota_reserve = magic == 0x31535251;
    value.checkpoint = get(); value.volume = get();
    if (value.quota_reserve) {
        value.quota_blocks = get(); value.reserve_blocks = get();
        const auto size = get();
        if (!valid || size != 80 || size > bytes.size() - at) return false;
        value.image_identity.assign(reinterpret_cast<const char*>(bytes.data()+at), size); at += size;
        if (value.image_identity.find_first_not_of("0123456789abcdef") != std::string::npos ||
            (value.quota_blocks && value.reserve_blocks > value.quota_blocks)) return false;
        const auto digest_size=get();
        if(!valid || digest_size!=64 || digest_size>bytes.size()-at)return false;
        value.space_census_sha256.assign(reinterpret_cast<const char*>(bytes.data()+at),digest_size);at+=digest_size;
        if(value.space_census_sha256.find_first_not_of("0123456789abcdef")!=std::string::npos)return false;
    }
    for (auto* s : {&value.container_uuid, &value.volume_uuid, &value.old_label, &value.new_label})
    {
        const auto size = get();
        if (!valid || size > 255 || size > bytes.size() - at) return false;
        s->assign(reinterpret_cast<const char*>(bytes.data() + at), static_cast<std::size_t>(size));
        at += static_cast<std::size_t>(size);
    }
    const auto size = get();
    if (!valid || size < 4096 || size > 65536 || (size & (size - 1)) || size != bytes.size() - at) return false;
    value.superblock.assign(bytes.begin() + at, bytes.end());
    const auto apsb = catalog::ParseApsb(value.superblock);
    if (!value.checkpoint || value.checkpoint == UINT64_MAX || !value.volume ||
        !ValidRenameUuid(value.container_uuid) || !ValidRenameUuid(value.volume_uuid) ||
        !ValidNativeVolumeLabel(value.old_label) || !ValidNativeVolumeLabel(value.new_label) ||
        (!value.quota_reserve && value.old_label == value.new_label) || !apsb || !apsb->name_valid ||
        apsb->object_id != value.volume || apsb->uuid_hex != value.volume_uuid ||
        apsb->name_utf8 != value.old_label || apsb->xid > value.checkpoint) return false;
    if (value.quota_reserve && (value.old_label != value.new_label ||
        (value.quota_blocks == apsb->space.quota_block_count && value.reserve_blocks == apsb->space.reserve_block_count) ||
        (value.quota_blocks && value.quota_blocks < apsb->space.allocated_block_count))) return false;
    out = std::move(value);
    return true;
}
inline bool DecodeNativeVolumeRename(std::span<const std::byte> bytes, NativeVolumeRename& out)
{ NativeVolumeRename value; if (!DecodeNativeVolumeMetadata(bytes, value) || value.quota_reserve) return false; out=std::move(value); return true; }
using NativeVolumeQuotaReserve = NativeVolumeRename;
inline bool DecodeNativeVolumeQuotaReserve(std::span<const std::byte> bytes, NativeVolumeQuotaReserve& out)
{ NativeVolumeRename value; if (!DecodeNativeVolumeMetadata(bytes, value) || !value.quota_reserve) return false; out=std::move(value); return true; }
inline std::vector<std::byte> EncodeNativeVolumeQuotaReserve(const NativeVolumeQuotaReserve& value)
{ return value.quota_reserve ? EncodeNativeVolumeRename(value) : std::vector<std::byte>{}; }

}
