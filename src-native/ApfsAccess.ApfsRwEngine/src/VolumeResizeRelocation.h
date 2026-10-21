#pragma once
#include "VolumeResizeInternal.h"
#include "VolumeFormatEvidence.h"

namespace apfsaccess::rw::volume_image
{
enum class ResizeTailRole : std::uint32_t
{
    Metadata = 1, Payload = 2, Queued = 4, Descriptor = 8,
    CheckpointData = 16, InternalPoolBitmap = 32, InternalPool = 64, Unknown = 128,
};
struct ResizeTailBlock
{
    std::uint64_t physical_block = 0;
    std::uint32_t roles = 0;
    format_evidence::Digest original_sha256{};
    bool Has(ResizeTailRole role) const { return (roles & static_cast<std::uint32_t>(role)) != 0; }
};
struct ResizeRelocationInventory
{
    std::vector<ResizeTailBlock> blocks;
    bool reserved_region_crosses_target = false;
    bool physical_snapshot_root_in_tail = false;
    std::size_t unknown_blocks = 0;
};
// Observation only. These blocks are neither writable nor releasable. The
// keeper's held source, CLEAN history and publication proofs remain required.
ResizeRelocationInventory InspectResizeRelocationSource(const catalog::RandomAccessSource&,
    const VolumeImageRequest&);
Plan BuildResizeRelocationPublication(const catalog::RandomAccessSource&, const VolumeImageRequest&);
// New original-journal profile; the legacy VIF5 planner remains unchanged.
Plan BuildResizeRelocationPublicationV2(const catalog::RandomAccessSource&, const VolumeImageRequest&);
}
