#pragma once
#include "VolumeFormat.h"
#include <set>
#include <stdexcept>
namespace apfsaccess::rw::volume_image
{
using Bytes = std::vector<std::byte>;
constexpr std::uint64_t Limit = 256ull * 1024 * 1024;
constexpr std::uint64_t StreamedFormatLimit = 1ull << 40;
constexpr std::uint32_t Block = 4096;
enum class ImageAdmission { BoundedImage, StreamedFormat, StreamedErase, StreamedResize };
inline void Require(bool ok, const std::string& error) { if (!ok) throw std::runtime_error(error); }
inline void Put(Bytes& b, std::size_t at, std::uint64_t value, unsigned width = 8)
{ for (unsigned i = 0; i < width; ++i) b.at(at + i) = std::byte((value >> (8 * i)) & 255); }
inline bool Bit(const Bytes& b, std::uint64_t n)
{ return !b.empty() && (std::to_integer<unsigned>(b.at(n / 8)) & (1u << (n % 8))); }
inline void SetBit(Bytes& b, std::uint64_t n, bool set)
{ const auto mask = std::byte(1u << (n % 8)); if (set) b.at(n / 8) |= mask; else b.at(n / 8) &= ~mask; }
inline void Checksum(Bytes& b)
{ std::string e; Require(FinalizeAppleObjectChecksum(b, e), e); }
struct Plan
{
    catalog::AppleCheckpointView before, after;
    AppleCheckpointPublicationPlan publication;
    Bytes anchor, postimage;
    std::set<std::uint64_t> destinations;
    std::vector<AppleCheckpointPhysicalWrite> cleanup;
};
struct Session;
class CleanImageHistoryAuthority final
{
public:
    CleanImageHistoryAuthority(const CleanImageHistoryAuthority&) = delete;
    CleanImageHistoryAuthority& operator=(const CleanImageHistoryAuthority&) = delete;
    void RequireFor(const Bytes& original, const VolumeImageRequest& request,
        const catalog::AppleCheckpointView& checkpoint) const
    {
        Require(&original == original_ && &request == request_ &&
            checkpoint.container.superblock.xid == checkpoint_xid_ &&
            checkpoint.container.superblock.uuid_hex == request.container_uuid &&
            checkpoint_xid_ == request.checkpoint_xid && source_identity_.size() == 80 && census_.size() == 64,
            "VolumeImageRetentionAuthorityBindingMismatch");
    }
private:
    friend struct Session;
    CleanImageHistoryAuthority(const Bytes& original, const VolumeImageRequest& request,
        std::uint64_t checkpoint_xid, std::string source_identity, std::string census)
        : original_(&original), request_(&request), checkpoint_xid_(checkpoint_xid),
          source_identity_(std::move(source_identity)), census_(std::move(census)) {}
    const Bytes* original_;
    const VolumeImageRequest* request_;
    std::uint64_t checkpoint_xid_;
    std::string source_identity_, census_;
};
bool IsFormat(VolumeImageOperation);
void ValidateRequest(const VolumeImageRequest&);
void ValidateRequest(const VolumeImageRequest&, ImageAdmission);
catalog::AppleCheckpointView Admit(const Bytes&, const VolumeImageRequest&);
catalog::AppleCheckpointView AdmitSource(const catalog::RandomAccessSource&, const VolumeImageRequest&, ImageAdmission);
void Verify(const Bytes&, const catalog::AppleCheckpointView&);
void VerifySource(const catalog::RandomAccessSource&, const catalog::AppleCheckpointView&);
void FinishPlan(const Bytes&, const VolumeImageRequest&, Plan&);
// Verifies both format publication stages without materializing an image-sized
// postimage. The caller must retain its exclusive source lease throughout.
void FinishFormatSource(const catalog::RandomAccessSource&, const VolumeImageRequest&, Plan&);
void FinishResizeSource(const catalog::RandomAccessSource&, const VolumeImageRequest&, Plan&);
// Legacy byte preservation plus a separately bounded v1 canonical-reset shrink.
// These restricted profiles are not universal APFS admission rules.
void ValidateResizeAllocationZones(const catalog::AppleSpacemanView&, std::uint64_t target_blocks);
Plan BuildResizePublication(const catalog::RandomAccessSource&, const VolumeImageRequest&, const catalog::AppleCheckpointView&);
Plan PlanResize(const Bytes&, const VolumeImageRequest&, const CleanImageHistoryAuthority* = nullptr);
// Pure layout construction; the keeper must first admit and authorize the source,
// then validate both publication stages with FinishPlan before returning intent.
Plan BuildFormatPublication(const catalog::RandomAccessSource&, const VolumeImageRequest&,
    const catalog::AppleCheckpointView&);
Plan PlanFormat(const Bytes&, const VolumeImageRequest&, const CleanImageHistoryAuthority* = nullptr);
Plan BuildFormatPublicationV2(const catalog::RandomAccessSource&, const VolumeImageRequest&,
    const catalog::AppleCheckpointView&);
Plan PlanFormatV2(const Bytes&, const VolumeImageRequest&, const CleanImageHistoryAuthority* = nullptr);
VolumeImageResult Prepare(const VolumeImageRequest&, bool format);
VolumeImageResult Run(const VolumeImageRequest&, std::string_view, bool format, bool recovery, bool cancel,
    const AppleCheckpointStageHook&);
}
