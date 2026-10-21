#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#ifdef _WIN32
#include <windows.h>
#endif

namespace apfsaccess::rw::windows_metadata
{
inline constexpr std::size_t SecurityPayloadLimit = 3804;
inline constexpr std::uint32_t PersistedAttributeMask = 0x1 | 0x2 | 0x4 | 0x20 | 0x100 | 0x2000;

// Shared with the host's persisted descriptor reader and writer. Windows APIs
// below are called only after every relative offset has been bounded.
inline bool ValidBoundedSecurity(std::span<const std::byte> bytes)
{
#ifdef _WIN32
    if (bytes.size() < sizeof(SECURITY_DESCRIPTOR_RELATIVE)) return false;
    SECURITY_DESCRIPTOR_RELATIVE header{};
    std::memcpy(&header, bytes.data(), sizeof(header));
    if (header.Revision != SECURITY_DESCRIPTOR_REVISION || !(header.Control & SE_SELF_RELATIVE)) return false;
    const auto contains = [&](std::size_t offset, std::size_t length) {
        return offset >= sizeof(header) && offset % sizeof(DWORD) == 0 &&
            offset <= bytes.size() && length <= bytes.size() - offset;
    };
    const auto valid_sid = [&](DWORD offset) {
        if (!offset) return true;
        if (!contains(offset, 8)) return false;
        const auto count = std::to_integer<unsigned>(bytes[offset + 1]);
        return count <= SID_MAX_SUB_AUTHORITIES && contains(offset, 8 + 4 * count) &&
            IsValidSid(const_cast<std::byte*>(bytes.data() + offset));
    };
    const auto valid_acl = [&](DWORD offset) {
        if (!offset) return true;
        if (!contains(offset, sizeof(ACL))) return false;
        ACL acl{};
        std::memcpy(&acl, bytes.data() + offset, sizeof(acl));
        if (acl.AclSize < sizeof(ACL) || !contains(offset, acl.AclSize)) return false;
        std::size_t cursor = sizeof(ACL);
        for (unsigned i = 0; i < acl.AceCount; ++i)
        {
            if (cursor > acl.AclSize || sizeof(ACE_HEADER) > acl.AclSize - cursor) return false;
            ACE_HEADER ace{};
            std::memcpy(&ace, bytes.data() + offset + cursor, sizeof(ace));
            if (ace.AceSize < sizeof(ACE_HEADER) || ace.AceSize % sizeof(DWORD) != 0 ||
                ace.AceSize > acl.AclSize - cursor) return false;
            cursor += ace.AceSize;
        }
        return IsValidAcl(reinterpret_cast<PACL>(const_cast<std::byte*>(bytes.data() + offset))) != FALSE;
    };
    if (!valid_sid(header.Owner) || !valid_sid(header.Group) ||
        !valid_acl(header.Dacl) || !valid_acl(header.Sacl)) return false;
    auto* descriptor = const_cast<std::byte*>(bytes.data());
    return IsValidSecurityDescriptor(descriptor) && GetSecurityDescriptorLength(descriptor) == bytes.size();
#else
    (void)bytes;
    return false;
#endif
}

inline bool ValidSecurityPayload(std::span<const std::byte> bytes)
{
    return bytes.size() >= 4 && bytes.size() <= SecurityPayloadLimit &&
        bytes[0] == std::byte{'W'} && bytes[1] == std::byte{'S'} &&
        bytes[2] == std::byte{'D'} && bytes[3] == std::byte{1} &&
        ValidBoundedSecurity(bytes.subspan(4));
}

inline bool DecodeAttributes(std::span<const std::byte> bytes, std::uint32_t& value)
{
    value = 0;
    if (bytes.size() != 8 || bytes[0] != std::byte{'D'} || bytes[1] != std::byte{'O'} ||
        bytes[2] != std::byte{'S'} || bytes[3] != std::byte{1}) return false;
    std::uint32_t decoded = 0;
    for (unsigned i = 0; i != 4; ++i)
        decoded |= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[4 + i])) << (8 * i);
    if ((decoded & ~PersistedAttributeMask) != 0) return false;
    value = decoded;
    return true;
}
}
