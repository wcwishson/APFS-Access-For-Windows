#pragma once
#include "NativeVolumeRename.h"

namespace apfsaccess::rw
{
// RCT2: one data-preserving APSB regular-file counter reconstruction.
// No offsets, replacement records, releases, or caller-chosen target bytes.
struct NativeCountRepair
{
    std::uint64_t checkpoint = 0, volume = 0, expected_count = 0;
    // graph_sha256 binds every current volume's complete FS and extentref
    // records, physical payload ranges, and actual contents. RCT1 lacked the
    // sibling inline-record proof and is deliberately not reinterpreted.
    std::string container_uuid, volume_uuid, source_identity, graph_sha256;
    std::vector<std::byte> superblock;
};
inline std::string CountRepairJournalIdentity(const NativeCountRepair& value)
{
    return "apfs-vol:" + value.container_uuid + ":" + std::to_string(value.volume);
}
inline std::vector<std::byte> EncodeNativeCountRepair(const NativeCountRepair& value)
{
    std::vector<std::byte> bytes;
    const auto put = [&](std::uint64_t n) {
        for (unsigned i = 0; i != 8; ++i) bytes.push_back(std::byte((n >> (8 * i)) & 255));
    };
    put(0x32544352); put(value.checkpoint); put(value.volume); put(value.expected_count);
    for (const auto* s : {&value.container_uuid, &value.volume_uuid, &value.source_identity, &value.graph_sha256}) {
        put(s->size()); for (unsigned char c : *s) bytes.push_back(std::byte(c));
    }
    put(value.superblock.size()); bytes.insert(bytes.end(), value.superblock.begin(), value.superblock.end());
    return bytes;
}
inline bool DecodeNativeCountRepair(std::span<const std::byte> bytes, NativeCountRepair& out)
{
    if (bytes.size() < 128 || bytes.size() > 67000) return false;
    std::size_t at = 0; bool valid = true;
    const auto get = [&]() {
        std::uint64_t n = 0;
        if (bytes.size() - at < 8) { valid = false; return n; }
        for (unsigned i = 0; i != 8; ++i) n |= std::uint64_t(std::to_integer<unsigned char>(bytes[at++])) << (8 * i);
        return n;
    };
    if (get() != 0x32544352) return false;
    NativeCountRepair value;
    value.checkpoint = get(); value.volume = get(); value.expected_count = get();
    for (auto* s : {&value.container_uuid, &value.volume_uuid, &value.source_identity, &value.graph_sha256}) {
        const auto size = get();
        if (!valid || size > 255 || size > bytes.size() - at) return false;
        s->assign(reinterpret_cast<const char*>(bytes.data() + at), static_cast<std::size_t>(size)); at += size;
    }
    const auto size = get();
    if (!valid || size < 4096 || size > 65536 || (size & (size - 1)) || size != bytes.size() - at) return false;
    value.superblock.assign(bytes.begin() + at, bytes.end());
    const auto apsb = catalog::ParseApsb(value.superblock);
    if (!value.checkpoint || value.checkpoint == UINT64_MAX || !value.volume ||
        !ValidRenameUuid(value.container_uuid) || !ValidRenameUuid(value.volume_uuid) ||
        value.source_identity.empty() || value.source_identity.find('\0') != std::string::npos ||
        value.graph_sha256.size() != 64 || value.graph_sha256.find_first_not_of("0123456789abcdef") != std::string::npos ||
        !apsb || apsb->object_id != value.volume || apsb->uuid_hex != value.volume_uuid ||
        apsb->xid > value.checkpoint || apsb->file_count == value.expected_count) return false;
    out = std::move(value); return true;
}
}
