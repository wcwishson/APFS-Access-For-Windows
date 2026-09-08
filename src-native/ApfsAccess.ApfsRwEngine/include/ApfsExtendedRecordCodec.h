#pragma once

#include "ApfsTransactionWriter.h"

#include <array>
#include <span>
#include <string>
#include <string_view>

namespace apfsaccess::rw
{

constexpr std::uint32_t kAppleBsdCompressedFlag = 0x00000020;
constexpr std::uint64_t kAppleInodeSparseFlag = 0x00000200;
constexpr std::uint8_t kAppleInodeSparseBytesField = 13;

// Fork/compression mutation requires an owner-aware policy. These names
// cannot enter the ordinary attribute writer through a lower-level caller.
constexpr bool IsOrdinaryAppleXattrName(std::string_view name)
{
    return !name.starts_with("com.apple.fs.") &&
        name != "com.apple.decmpfs" && name != "com.apple.ResourceFork";
}

// Both trees must supply an admitted inode. A missing original is allowed only
// for a genuinely new owner; a missing requested inode only for final deletion.
// Keep this independent of projected NodeType so raw planner callers use modes.
constexpr bool IsUncompressedAppleResourceForkOwner(
    std::uint64_t object_id, std::uint64_t private_id, std::uint16_t mode,
    std::uint32_t bsd_flags, bool has_decmpfs)
{
    return object_id > 2 && object_id < 0x0fffffffffffffffULL &&
        private_id != 0 && private_id < 0x0fffffffffffffffULL &&
        (mode & 0170000) == 0100000 &&
        (bsd_flags & kAppleBsdCompressedFlag) == 0 && !has_decmpfs;
}

struct AppleSecurityAce
{
    std::array<std::byte, 16> applicable{};
    std::uint32_t flags = 0;
    std::uint32_t rights = 0;
};

enum class ApplePrincipalKind { Uid, Gid, Owner, Group, Everybody, Nobody };

struct AppleSecurityPrincipal
{
    ApplePrincipalKind kind = ApplePrincipalKind::Nobody;
    std::uint32_t id = 0; // Must be zero for symbolic principals.
};

enum class ProjectedAceKind { Allow, Deny };

struct ProjectedSecurityAce
{
    AppleSecurityPrincipal principal;
    ProjectedAceKind kind = ProjectedAceKind::Allow;
    std::uint32_t access_mask = 0; // Exact Windows file-specific/standard rights.
    std::uint8_t ace_flags = 0; // Numeric Windows inheritance flags only.
};

struct AppleSecurityRecord
{
    std::array<std::byte, 16> owner{};
    std::array<std::byte, 16> group{};
    bool no_acl = false;
    std::uint32_t acl_flags = 0; // Only meaningful when no_acl is false.
    // XNU skips swapping these bytes for NOACL; their semantic meaning is undefined.
    // Preserve them unchanged, never interpret them as acl_flags or update them.
    std::array<std::byte, 4> no_acl_flags{};
    std::vector<AppleSecurityAce> entries;
};

class ApfsExtendedRecordCodec
{
public:
    // Bounded semantic projection only; false means unsupported, with output unchanged.
    // No SID resolution, generic-right expansion, ownership policy or ACL rewriting.
    [[nodiscard]] static bool DecodeSecurityPrincipal(
        const std::array<std::byte, 16>& guid, AppleSecurityPrincipal& out_principal,
        std::string& out_error);
    [[nodiscard]] static bool EncodeSecurityPrincipal(
        const AppleSecurityPrincipal& principal, std::array<std::byte, 16>& out_guid,
        std::string& out_error);
    [[nodiscard]] static bool ProjectSecurityAce(
        const AppleSecurityAce& ace, ProjectedSecurityAce& out_ace, std::string& out_error);
    [[nodiscard]] static bool UnprojectSecurityAce(
        const ProjectedSecurityAce& ace, AppleSecurityAce& out_ace, std::string& out_error);

    // Structural com.apple.system.Security codec only: no permission or capability decisions.
    // Exactly 44 + 24 * count bytes, count <= 128; NOACL is distinct from an empty ACL.
    [[nodiscard]] static bool DecodeSecurity(
        std::span<const std::byte> bytes, AppleSecurityRecord& out_security,
        std::string& out_error);
    [[nodiscard]] static bool EncodeSecurity(
        const AppleSecurityRecord& security, std::vector<std::byte>& out_bytes,
        std::string& out_error);

    [[nodiscard]] static bool DecodeInode(
        const catalog::BtreeRecord& record,
        AppleInodeRecord& out_inode,
        std::string& out_error);

    [[nodiscard]] static bool DecodeSiblingLink(
        const catalog::BtreeRecord& record,
        AppleSiblingLinkRecord& out_link,
        std::string& out_error);

    [[nodiscard]] static bool DecodeSiblingMap(
        const catalog::BtreeRecord& record,
        AppleSiblingMapRecord& out_map,
        std::string& out_error);

    [[nodiscard]] static bool DecodeXattr(
        const catalog::BtreeRecord& record,
        AppleXattrRecord& out_xattr,
        std::string& out_error);
};

} // namespace apfsaccess::rw
