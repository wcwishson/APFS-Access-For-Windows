#pragma once
#include <cstdint>
#include <cstddef>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace apfsaccess::rw
{
class BlockDevice;
class VolumePhysicalSource;
struct RawSnapshotBinding;
enum class VolumeKeeperAdmissionScope : std::uint8_t { All, ForeignToManagement, ForeignToImage };
enum class VolumeKeeperJournalState : std::uint8_t { Missing, Prepared, Accepted, AnchorDurable, Completed, Cancelled, Invalid };
struct VolumeKeeperJournalEvidence
{
    std::string family, error;
    std::filesystem::path path;
    VolumeKeeperJournalState state = VolumeKeeperJournalState::Invalid;
};
struct VolumeKeeperAdmission
{
    bool admitted = false;
    std::string error, source_identity, locator;
    std::vector<VolumeKeeperJournalEvidence> journals;
};
struct VolumeKeeperHistoryMember
{
    std::string container_uuid, volume_uuid;
    std::uint64_t oid = 0;
    std::filesystem::path wal;
};
// Native-only projection of the same validated keeper frame used by admission.
// It is decoded again from held bytes wherever history authorizes continuation.
struct VolumeKeeperHistoryBinding
{
    VolumeKeeperJournalState state = VolumeKeeperJournalState::Invalid;
    bool image_family = false;
    std::uint64_t operation = 0, pre_xid = 0, post_xid = 0;
    std::string source_identity, token, frame_digest, census_digest;
    std::filesystem::path image, journal;
    std::vector<VolumeKeeperHistoryMember> before, after;
};
VolumeKeeperHistoryBinding DecodeVolumeKeeperHistoryBinding(std::span<const std::byte> bytes,
    const std::filesystem::path& journal, const std::filesystem::path& trusted_root,
    std::string_view held_identity);
// Additional physical mode/binding check; this does not mint a source lease.
void ValidateVolumeKeeperPhysicalFrame(std::span<const std::byte>, const VolumePhysicalSource&);
RawSnapshotBinding DecodeVolumeKeeperPhysicalBinding(std::span<const std::byte>);
// Native keeper preflight. identity MUST be obtained from the already-held,
// exclusive ordinary image (QueryRegularImageIdentity or its handle equivalent),
// never from a request/client. Keep that image lease through the entire operation.
// The trusted private journal root is shared by every family and stable on restart.
// All family frames in that root are bound to their stored file ID and interval.
// Whole-image geometry debt covers every offset of the same file. Unbindable
// evidence fails closed even when its filename is not the requested locator.
// Only the owning keeper may exclude its own exact family/offset for recovery.
VolumeKeeperAdmission InspectHeldVolumeKeeperJournals(const std::filesystem::path& trusted_root,
    std::string_view held_identity, VolumeKeeperAdmissionScope scope = VolumeKeeperAdmissionScope::All);
// Read-only bootstrap observation: opens a stable ordinary image, checks ALL
// families, and releases its lease on return. This is not a transferable mutation
// authorization. Runtime must repeat admission under its own held source lease.
VolumeKeeperAdmission InspectVolumeKeeperImage(const std::filesystem::path& image,
    std::uint64_t offset_bytes, const std::filesystem::path& trusted_root);
// Runtime bridge: no source reopen. Caller retains an exclusive image handle
// through replay, mount and every commit (OpenExclusiveManagementImage or the
// coordinator's exclusive-image mode). Historical/unknown sources fail closed.
VolumeKeeperAdmission InspectHeldVolumeKeeperImage(const BlockDevice& source,
    const std::filesystem::path& trusted_root, bool historical_source = false);
// Source-only observation on an already accepted raw writer; never admits or
// reopens a device. Hardware and instance identity are derived from that source.
VolumeKeeperAdmission InspectHeldVolumeKeeperRaw(const BlockDevice& source,
    const std::filesystem::path& trusted_root);
std::string VolumeKeeperAdmissionJson(const VolumeKeeperAdmission&);
}
