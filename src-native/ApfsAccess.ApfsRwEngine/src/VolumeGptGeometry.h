#pragma once
#include "VolumePhysicalBindingCodec.h"
#include <functional>

namespace apfsaccess::rw::volume_geometry
{
inline constexpr std::uint64_t Magic = 0x3746495653465041ull;
inline constexpr std::uint64_t Version2Magic = 0x3846495653465041ull;
inline constexpr std::uint64_t PhysicalSnapshotRelocationMagic = 0x3946495653465041ull;
enum class Profile : std::uint64_t { LegacyPartition = 0, Partition = 1, ContainerWindow = 2 };
inline bool IsMagic(std::uint64_t magic) { return magic == Magic || magic == Version2Magic; }
using Bytes = std::vector<std::byte>;
struct Snapshot
{
    volume_physical::Envelope original;
    std::uint64_t target_bytes = 0;
    Bytes mbr, primary_header, backup_header, primary_array, backup_array;
    Profile profile = Profile::LegacyPartition;
};
struct Write
{
    std::uint64_t offset = 0;
    Bytes before, after;
};
struct Plan
{
    Snapshot snapshot;
    RawSnapshotBinding after;
    std::vector<Write> writes;
};
inline std::uint64_t MagicOf(const Plan& plan)
{ return plan.snapshot.profile == Profile::LegacyPartition ? Magic : Version2Magic; }
std::uint32_t Crc32(std::span<const std::byte>);
Plan Build(Snapshot);
Plan Capture(const catalog::RandomAccessSource& whole_disk, const volume_physical::Envelope&, std::uint64_t target_bytes);
Bytes Encode(const Plan&);
Plan Decode(std::span<const std::byte>);
bool Follows(const Plan& completed, const Plan& next);
void Verify(const catalog::RandomAccessSource& whole_disk, const Plan&, unsigned state);
void Publish(const Plan&, const std::function<bool(std::uint64_t, std::span<const std::byte>)>& write,
    const std::function<bool()>& flush, const catalog::RandomAccessSource& readback, const AppleCheckpointStageHook&);
}

namespace apfsaccess::rw {
volume_geometry::Plan DecodeVolumeKeeperGeometryPlan(std::span<const std::byte>);
}
