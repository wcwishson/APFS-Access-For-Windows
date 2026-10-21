#pragma once

#include "ApfsContainerCatalog.h"
#include "NativeApfsReader.h"

#include <map>
#include <memory>
#include <span>

namespace apfsaccess::rw
{
// APFS Reference (2020-06-22), p. 98. Only the attribute NAME is specified.
inline constexpr std::string_view kFirmlinkEaName = "com.apple.fs.firmlink";
enum class FirmlinkDecodeStatus { NotFirmlink, UnsupportedSerialization };
// Consumes the existing xattr codec's result. Never interprets data or flags,
// resolves a path, reads an external stream, or produces a verified route.
[[nodiscard]] FirmlinkDecodeStatus InspectFirmlinkAttribute(const AppleXattrRecord& attribute) noexcept;

// Reuse native catalog volume identity; inode OIDs alone are volume-local.
// checkpoint_xid pins the read view; inode_xid retains the projection's xid.
struct FirmlinkObjectIdentity
{
    catalog::ResolvedMountVolume volume;
    std::uint64_t object_id = 0;
    std::uint64_t checkpoint_xid = 0;
    std::uint64_t inode_xid = 0;
};

struct VerifiedFirmlinkRecord
{
    FirmlinkObjectIdentity source;
    FirmlinkObjectIdentity target;
};

enum class FirmlinkViewPolicy { IndependentVolume, ReadOnlyUnifiedGroup };
enum class FirmlinkTraversal { Forward, Parent };
enum class FirmlinkAccess { Read, Mutation };

// Directory identity routing foundation, NOT image-derived firmlink support.
// The caller must bind both projections to the strict catalog's device and
// checkpoint, and supply independently verified pairs. The builder checks
// identity/topology consistency; it cannot authenticate the origin of a pair.
// No current production reader can produce VerifiedFirmlinkRecord from bytes.
class ApfsFirmlinkRouter final
{
public:
    static constexpr std::size_t kMaxTraversalSteps = 256;
    static constexpr std::size_t kMaxProjectionInodes = 1'000'000;
    static constexpr std::size_t kMaxDirectoryLinks = 2'000'000;
    static constexpr std::size_t kMaxRecords = 65'536;

    [[nodiscard]] static bool TryBuild(
        const catalog::ApfsContainerDescriptor& container,
        const std::string& group_uuid_hex,
        const NativeApfsVolumeProjection& system,
        const NativeApfsVolumeProjection& data,
        std::span<const VerifiedFirmlinkRecord> records,
        std::shared_ptr<const ApfsFirmlinkRouter>& out,
        std::string& error);

    // IndependentVolume returns the input unchanged (also for Mutation);
    // that is a bypass, NEVER write authorization or a parent lookup.
    // Unified Mutation is always refused, even if no crossing would occur.
    // Unified reads accept directories only. Resolve leaf files with their
    // existing backing MetadataStore after routing the containing directory.
    // A failure clears out; successful output retains backing volume and xids.
    [[nodiscard]] bool TryRoute(const FirmlinkObjectIdentity& input,
        FirmlinkViewPolicy view, FirmlinkTraversal traversal, FirmlinkAccess access,
        FirmlinkObjectIdentity& out, std::string& error) const;

private:
    using Key = std::pair<std::uint64_t, std::uint64_t>; // volume OID, inode OID
    struct Directory
    {
        FirmlinkObjectIdentity identity;
        Key parent;
    };
    ApfsFirmlinkRouter() = default;
    [[nodiscard]] bool Matches(const FirmlinkObjectIdentity& value) const;
    [[nodiscard]] bool Forward(Key input, Key& out, std::string& error) const;
    [[nodiscard]] bool Parent(Key input, Key& out, std::string& error) const;
    [[nodiscard]] bool ValidateChains(std::string& error) const;
    [[nodiscard]] bool ValidateUnnestedCrossings(std::string& error) const;
    std::map<Key, Directory> directories_;
    std::map<Key, Key> forward_;
    std::map<Key, Key> reverse_;
};
} // namespace apfsaccess::rw
